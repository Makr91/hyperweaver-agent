package server

// Task-queued /filesystem operations: move and copy (zoneweaver's file_move /
// file_copy — async because trees can be huge). Rows ride machine_name
// "filesystem", exempt from per-machine exclusivity like the base's scope.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

const (
	opFileMove           = "file_move"
	opFileCopy           = "file_copy"
	opFileArchiveCreate  = "file_archive_create"
	opFileArchiveExtract = "file_archive_extract"

	filesystemTaskMachine = "filesystem"
)

type fileTransferMetadata struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// transferTaskResponse is the 202 body of PUT /filesystem/move and
// POST /filesystem/copy: the queued file_move / file_copy task's id alongside
// the source and destination it will act on.
type transferTaskResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	TaskID      string `json:"task_id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// registerFilesystemExecutors wires the filesystem task operations; called
// from New (before the queue starts).
func (s *Server) registerFilesystemExecutors() {
	s.tasks.Register(opFileMove, tasks.Executor{Run: s.fileMoveTask})
	s.tasks.Register(opFileCopy, tasks.Executor{Run: s.fileCopyTask})
	s.tasks.Register(opFileArchiveCreate, tasks.Executor{Run: s.archiveCreateTask})
	s.tasks.Register(opFileArchiveExtract, tasks.Executor{Run: s.archiveExtractTask})
}

// queueFilesystemTask creates one filesystem task row; this swag block
// documents the copy action (the move action rides handleTransferItem, which
// shares this helper).
//
//	@Summary		Copy an item (task)
//	@Description	Minimum role: operator. {source, destination} → 202 file_copy task. Directories copy recursively; symlinks and specials are skipped, never followed.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	fileTransferMetadata	true	"Source and destination paths"
//	@Success		202	{object}	transferTaskResponse	"Copy task created ({success, message, task_id, source, destination})"
//	@Failure		400	"Missing fields"
//	@Failure		403	"Path forbidden"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/copy [post]
func (s *Server) queueFilesystemTask(r *http.Request, operation string, priority int, metadata any) (*tasks.Task, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	encoded := string(raw)
	return s.tasks.Store().Create(r.Context(), &tasks.NewTask{
		MachineName: filesystemTaskMachine,
		Operation:   operation,
		Priority:    priority,
		CreatedBy:   auth.FromContext(r.Context()).Name,
		Metadata:    &encoded,
	})
}

// handleTransferItem serves PUT /filesystem/move and POST /filesystem/copy —
// {source, destination} → 202 with the task id.
//
//	@Summary		Move an item (task)
//	@Description	Minimum role: operator. {source, destination} → 202 file_move task (async — trees can be huge). Rename first; a cross-volume move copies then deletes the source.
//	@Tags			File System
//	@Accept			json
//	@Produce		json
//	@Param			request	body	fileTransferMetadata	true	"Source and destination paths"
//	@Success		202	{object}	transferTaskResponse	"Move task created ({success, message, task_id, source, destination})"
//	@Failure		400	"Missing fields"
//	@Failure		403	"Path forbidden"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem/move [put]
func (s *Server) handleTransferItem(operation, verb string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body fileTransferMetadata
		if err := decodeBody(r, &body); err != nil {
			taskError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if body.Source == "" || body.Destination == "" {
			taskError(w, http.StatusBadRequest, "source and destination are required")
			return
		}
		// Validation up front so a doomed task never queues; the executor
		// re-validates (the bounds may have changed by run time).
		if _, err := s.validateBrowsePath(body.Source); err != nil {
			writeBrowseError(w, err, "Failed to create "+verb+" task")
			return
		}
		if _, err := s.validateBrowsePath(body.Destination); err != nil {
			writeBrowseError(w, err, "Failed to create "+verb+" task")
			return
		}
		task, err := s.queueFilesystemTask(r, operation, tasks.PriorityMedium, &body)
		if err != nil {
			taskError(w, http.StatusInternalServerError, "Failed to create "+verb+" task")
			return
		}
		writeJSONStatus(w, http.StatusAccepted, transferTaskResponse{
			Success:     true,
			Message:     capitalize(verb) + " task created for '" + filepath.Base(body.Source) + "'",
			TaskID:      task.ID,
			Source:      body.Source,
			Destination: body.Destination,
		})
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// transferPaths re-validates a transfer task's endpoints at run time.
func (s *Server) transferPaths(task *tasks.Task) (source, destination string, err error) {
	var meta fileTransferMetadata
	if task.Metadata == nil {
		return "", "", errors.New(task.Operation + " task has no metadata")
	}
	if uerr := json.Unmarshal([]byte(*task.Metadata), &meta); uerr != nil {
		return "", "", uerr
	}
	source, err = s.validateBrowsePath(meta.Source)
	if err != nil {
		return "", "", err
	}
	destination, err = s.validateBrowsePath(meta.Destination)
	if err != nil {
		return "", "", err
	}
	return source, destination, nil
}

func (s *Server) fileMoveTask(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	source, destination, err := s.transferPaths(task)
	if err != nil {
		return err
	}
	out.Write("stdout", "Moving "+source+" -> "+destination+"\n")
	if rerr := os.Rename(source, destination); rerr != nil {
		// Cross-volume: copy then delete.
		out.Write("stdout", "Rename failed ("+rerr.Error()+"); copying across volumes\n")
		if cerr := copyPath(ctx, source, destination); cerr != nil {
			return cerr
		}
		if derr := os.RemoveAll(source); derr != nil {
			out.Write("stderr", "Source removal after copy failed: "+derr.Error()+"\n")
			return derr
		}
	}
	out.Write("stdout", "Move complete\n")
	return nil
}

func (s *Server) fileCopyTask(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	source, destination, err := s.transferPaths(task)
	if err != nil {
		return err
	}
	out.Write("stdout", "Copying "+source+" -> "+destination+"\n")
	if cerr := copyPath(ctx, source, destination); cerr != nil {
		return cerr
	}
	out.Write("stdout", "Copy complete\n")
	return nil
}

// copyPath copies a file or a whole tree, honoring ctx between entries.
func copyPath(ctx context.Context, source, destination string) error {
	info, err := os.Stat(filepath.Clean(source))
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return copyOneFile(source, destination, info.Mode().Perm())
	}
	return filepath.WalkDir(source, func(entry string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, rerr := filepath.Rel(source, entry)
		if rerr != nil {
			return rerr
		}
		target := destination
		if rel != "." {
			target = filepath.Join(destination, rel)
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		if !d.Type().IsRegular() {
			return nil // symlinks and specials are skipped, never followed
		}
		einfo, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		return copyOneFile(entry, target, einfo.Mode().Perm())
	})
}

func copyOneFile(source, destination string, mode os.FileMode) error {
	in, err := os.Open(filepath.Clean(source))
	if err != nil {
		return err
	}
	defer func() {
		_ = in.Close()
	}()
	if _, werr := safepath.WriteFileFrom(destination, in, 0o600); werr != nil {
		_ = os.Remove(destination)
		return werr
	}
	if cerr := os.Chmod(destination, mode); cerr != nil {
		return cerr
	}
	return nil
}

// copyChunks streams src to dst in bounded chunks, honoring ctx — the
// cancellable copy every archive path uses.
func copyChunks(ctx context.Context, dst io.Writer, src io.Reader) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		_, err := io.CopyN(dst, src, 1<<20)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
