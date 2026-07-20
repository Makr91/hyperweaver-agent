package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// importUploadMaxBytes caps one provisioner import-upload body — far above
// any real package archive.
const importUploadMaxBytes = int64(4) << 30

// handleExportProvisionerVersion queues provisioner_export (design §7's
// share half): the version → one registry-shaped tar.gz + the archive's
// sha256 (task output + .sha256 sidecar) under <registry>/exports.
//
//	@Summary		Export a version as a shareable archive
//	@Description	Minimum role: operator. Queues provisioner_export (design §7's host-to-host share): the version becomes ONE tar.gz — REGISTRY-SHAPED (<name>/<version>/… inside the tar, so the receiving agent's ordinary import consumes it) — under <registry>/exports, with the sha256 OF THE ARCHIVE (whole-file only) in the task output and a `<file>.sha256` sidecar beside it. Symlinks and specials never enter the archive.
//	@Tags			Provisioning
//	@Produce		json
//	@Param			name	path	string	true	"Provisioner family name"
//	@Param			version	path	string	true	"Version string or directory name"
//	@Success		202	"Export task queued"
//	@Failure		404	"Provisioner or version not found"
//	@Router			/provisioning/provisioners/{name}/versions/{version}/export [post]
func (s *Server) handleExportProvisionerVersion(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	version, err := s.provisioners.GetVersion(name, r.PathValue("version"))
	if errors.Is(err, provisioner.ErrNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner not found")
		return
	}
	if errors.Is(err, provisioner.ErrVersionNotFound) {
		taskError(w, http.StatusNotFound, "Provisioner version not found")
		return
	}
	if err != nil {
		slog.Error("get provisioner version for export", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue export task")
		return
	}

	raw, err := json.Marshal(&provisioner.ExportMetadata{Name: name, Version: version.Version})
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to queue export task")
		return
	}
	metadata := string(raw)
	task, err := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: "system",
		Operation:   provisioner.OpExport,
		Priority:    tasks.PriorityMedium,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &metadata,
	})
	if err != nil {
		slog.Error("queue provisioner export", "name", name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to queue export task")
		return
	}
	acceptedTask(w, task.ID, "Export task queued for "+name+"/"+version.Version)
}

// handleImportUploadProvisioner receives a package archive as multipart
// form-data (part name "file") and queues the ordinary import task against
// it — the share contract's receiving half. The temp archive cleans up after
// the import attempt (cleanup_source). An optional "checksum" field (sha256
// of the archive — the converged wire, sync 2026-07-17) rides into the
// import's pre-extraction verification; like the file-manager precedent,
// non-file fields must arrive BEFORE the file part — the stream is consumed
// in order and the task queues the moment the file lands.
//
//	@Summary		Upload a package archive and import it
//	@Description	Minimum role: operator. The share contract's receiving half: multipart/form-data with a "file" part (.tar.gz/.tgz/.zip, ≤4 GiB) streams to a temp file and queues the ordinary provisioner_import task against it (same DSL lint gate, same non-clobber rules; the temp archive removes itself after the attempt). An optional checksum field — the sender's published sha256 OF THE ARCHIVE (64 hex chars; the converged wire, sync 2026-07-17) — rides into the import's pre-extraction verification: a mismatch fails the task honestly, nothing extracts. Like the file-manager upload, non-file fields must arrive BEFORE the file part — the stream is consumed in order and the task queues the moment the file lands.
//	@Tags			Provisioning
//	@Accept			mpfd
//	@Produce		json
//	@Param			checksum	formData	string	false	"Optional sha256 hex digest (64 characters) of the archive, verified before extraction — must precede the file part"
//	@Param			file	formData	file	true	"The package archive (.tar.gz, .tgz, or .zip; ≤4 GiB)"
//	@Success		202	"Import task queued ({success, task_id, filename, size, status, message})"
//	@Failure		400	"Not multipart, no file part, not a supported archive name, or an invalid checksum ("checksum must be a 64-character sha256 hex digest")"
//	@Failure		413	"Upload exceeds the 4 GiB cap"
//	@Router			/provisioning/provisioners/import-upload [post]
func (s *Server) handleImportUploadProvisioner(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importUploadMaxBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		taskError(w, http.StatusBadRequest, "multipart/form-data with a file part is required")
		return
	}
	checksum := ""
	for {
		part, perr := reader.NextPart()
		if errors.Is(perr, io.EOF) {
			taskError(w, http.StatusBadRequest, `no "file" part in the upload`)
			return
		}
		if perr != nil {
			taskError(w, http.StatusBadRequest, "Malformed multipart body: "+perr.Error())
			return
		}
		if part.FormName() == "checksum" {
			raw, rerr := io.ReadAll(io.LimitReader(part, 4096))
			if rerr != nil {
				taskError(w, http.StatusBadRequest, "Malformed multipart body: "+rerr.Error())
				return
			}
			checksum = strings.TrimSpace(string(raw))
			continue
		}
		if part.FormName() != "file" {
			continue
		}
		filename := filepath.Base(part.FileName())
		if filename == "" || filename == "." || !provisioner.IsArchiveName(filename) {
			taskError(w, http.StatusBadRequest, "the uploaded file must be a .tar.gz, .tgz, or .zip package archive")
			return
		}

		temp, terr := os.MkdirTemp("", "hyperweaver-upload-*")
		if terr != nil {
			slog.Error("create upload temp dir", "error", terr)
			taskError(w, http.StatusInternalServerError, "Failed to receive upload")
			return
		}
		archivePath := filepath.Join(temp, filename)
		size, werr := safepath.WriteFileFrom(archivePath, part, 0o600)
		if werr != nil {
			_ = os.RemoveAll(temp)
			var tooLarge *http.MaxBytesError
			if errors.As(werr, &tooLarge) {
				taskError(w, http.StatusRequestEntityTooLarge, "Upload exceeds the import size cap")
				return
			}
			slog.Error("receive provisioner upload", "error", werr)
			taskError(w, http.StatusInternalServerError, "Failed to receive upload")
			return
		}

		meta := &provisioner.ImportMetadata{
			SourceType:    provisioner.SourceArchive,
			Path:          archivePath,
			CleanupSource: true,
			Checksum:      checksum,
		}
		if verr := meta.Validate(); verr != nil {
			_ = os.RemoveAll(temp)
			taskError(w, http.StatusBadRequest, verr.Error())
			return
		}
		raw, merr := json.Marshal(meta)
		if merr != nil {
			_ = os.RemoveAll(temp)
			taskError(w, http.StatusInternalServerError, "Failed to queue import task")
			return
		}
		metadata := string(raw)
		task, cerr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: "system",
			Operation:   provisioner.OpImport,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
			Metadata:    &metadata,
		})
		if cerr != nil {
			_ = os.RemoveAll(temp)
			slog.Error("queue uploaded provisioner import", "error", cerr)
			taskError(w, http.StatusInternalServerError, "Failed to queue import task")
			return
		}
		slog.Info("provisioner upload received", "filename", filename, "bytes", size,
			"task_id", task.ID, "by", auth.FromContext(r.Context()).Name)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if werr := json.NewEncoder(w).Encode(map[string]any{
			"success":  true,
			"task_id":  task.ID,
			"filename": filename,
			"size":     size,
			"status":   tasks.StatusPending,
			"message":  "Provisioner import task queued from upload",
		}); werr != nil {
			slog.Error("write import-upload response", "error", werr)
		}
		return
	}
}
