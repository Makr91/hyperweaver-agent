package machines

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// Template export — the base's template_export (zone → local .box via zfs
// send) in VirtualBox terms: `VBoxManage export` writes the machine as
// OVF + disk images, metadata.json marks the provider, and the tarball is a
// standard Vagrant virtualbox box. Boxes land under <templates root>/exports.

// OpTemplateExport is the export task operation.
const OpTemplateExport = "template_export"

// templateExportMetadata is the export task's metadata ({filename} — the
// machine rides task.MachineName so per-machine exclusivity serializes the
// export against lifecycle).
type templateExportMetadata struct {
	Filename string `json:"filename,omitempty"`
}

// templateExport executes one template_export task.
func (e *executors) templateExport(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	machine, vboxExe, err := e.resolve(ctx, task)
	if err != nil {
		return err
	}
	var meta templateExportMetadata
	if task.Metadata != nil {
		if uerr := json.Unmarshal([]byte(*task.Metadata), &meta); uerr != nil {
			return fmt.Errorf("parse export metadata: %w", uerr)
		}
	}

	filename := meta.Filename
	if filename == "" {
		filename = fmt.Sprintf("%s-%d.box", provisioner.MachineDirName(machine.Name), time.Now().Unix())
	}
	boxPath, checksum, err := e.buildMachineBox(ctx, task, machine, vboxExe, filename, out)
	if err != nil {
		return err
	}

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Exported "+machine.Name+" to "+boxPath+" (sha256 "+checksum+")\n")
	return nil
}

// buildMachineBox exports a powered-off machine as a Vagrant virtualbox .box
// under <templates root>/exports/<filename>, returning the path and sha256 —
// the base's createBoxArtifact (zfs send → box.zss) as VBoxManage export →
// OVF. Shared by template_export and template_upload.
func (e *executors) buildMachineBox(ctx context.Context, task *tasks.Task,
	machine *Machine, vboxExe, filename string, out *tasks.OutputWriter,
) (boxPath, checksum string, err error) {
	target := machine.VBoxTarget()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, target)
	if err != nil {
		return "", "", fmt.Errorf("machine has no VM to export: %w", err)
	}
	if MapVBoxState(info.State) == StatusRunning {
		return "", "", errors.New("machine is running — VirtualBox exports powered-off machines; stop it first")
	}

	exportsDir := filepath.Join(e.env.TemplatesDir, "exports")
	if merr := os.MkdirAll(exportsDir, 0o750); merr != nil {
		return "", "", merr
	}
	tempDir, err := os.MkdirTemp(exportsDir, "export-")
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	e.taskProgress(task, 10, "exporting_appliance")
	out.Write("stdout", "Exporting "+machine.Name+" (VBoxManage export → OVF)\n")
	if xerr := vbox.ExportVM(ctx, vboxExe, target, filepath.Join(tempDir, "box.ovf")); xerr != nil {
		return "", "", xerr
	}

	e.taskProgress(task, 60, "creating_metadata")
	metadata, err := json.Marshal(map[string]string{
		"provider":   "virtualbox",
		"created_at": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return "", "", err
	}
	if werr := safepath.WriteFile(filepath.Join(tempDir, "metadata.json"), metadata, 0o600); werr != nil {
		return "", "", werr
	}
	vagrantfile := "Vagrant.configure(\"2\") do |config|\n  config.vm.provider :virtualbox\nend\n"
	if werr := safepath.WriteFile(filepath.Join(tempDir, "Vagrantfile"), []byte(vagrantfile), 0o600); werr != nil {
		return "", "", werr
	}

	e.taskProgress(task, 70, "packaging_box")
	boxPath, err = safepath.Under(exportsDir, filename)
	if err != nil {
		return "", "", fmt.Errorf("filename is not usable: %w", err)
	}
	checksum, err = packBox(tempDir, boxPath)
	if err != nil {
		return "", "", err
	}
	return boxPath, checksum, nil
}

// packBox tars and gzips every file in dir into a .box, returning its sha256.
// The archive streams through a pipe into safepath.WriteFileFrom — the
// agent's ONE file-write path.
func packBox(dir, boxPath string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	reader, writer := io.Pipe()

	go func() {
		zipper := gzip.NewWriter(io.MultiWriter(writer, hasher))
		archive := tar.NewWriter(zipper)
		pack := func() error {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				info, ierr := entry.Info()
				if ierr != nil {
					return ierr
				}
				header := &tar.Header{
					Name: entry.Name(),
					Mode: 0o644,
					Size: info.Size(),
				}
				if herr := archive.WriteHeader(header); herr != nil {
					return herr
				}
				source, oerr := os.Open(filepath.Clean(filepath.Join(dir, entry.Name())))
				if oerr != nil {
					return oerr
				}
				_, cerr := io.Copy(archive, source)
				_ = source.Close()
				if cerr != nil {
					return cerr
				}
			}
			if cerr := archive.Close(); cerr != nil {
				return cerr
			}
			return zipper.Close()
		}
		writer.CloseWithError(pack())
	}()

	if _, werr := safepath.WriteFileFrom(boxPath, reader, 0o600); werr != nil {
		return "", werr
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
