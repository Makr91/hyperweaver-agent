package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// createStorage executes machine_create_storage: resolve the template
// (post-download re-resolution included), clone its disk image as the boot
// medium, grow it to disks.boot.size, create the additional media — every
// created medium tracked for reverse-order rollback (StorageManager 1:1; on
// this hypervisor the boot disk IS the box's disk image).
func (e *executors) createStorage(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	meta, err := readCreateMetadata(task)
	if err != nil {
		return err
	}
	var output *createExecutionOutput
	if meta.Spec.HasProvisioner() {
		output, err = e.dependencyOutput(ctx, task)
		if err != nil {
			return err
		}
	} else {
		// No prepare child ran — the base's shape (its chain has no render
		// step; the create body IS the document): build the document straight
		// from the spec. Provisioning attaches later via PUT, never here.
		// Marshal order is irrelevant on this path — no provisioner section
		// exists (only the provisioner document's key order is load-bearing).
		out.Write("stdout", "Provisioner-less create — building the document from the spec\n")
		raw, merr := json.Marshal(specDocument(ctx, e.env, meta.Spec))
		if merr != nil {
			return merr
		}
		output = &createExecutionOutput{Document: raw}
	}
	document := parseConfigBytes(output.Document)
	settings := document.Section("settings")
	disks := document.Section("disks")

	if meta.Spec.Hypervisor == HypervisorUTM {
		return e.createStorageUTM(ctx, task, meta.Spec, output, settings, out)
	}

	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	workdir := e.machineWorkdir(task.MachineName)
	// prepare's materialize normally creates the working directory; a
	// provisioner-less create has no prepare, so ensure it (idempotent) —
	// media land in it either way.
	if merr := os.MkdirAll(workdir, 0o750); merr != nil {
		return merr
	}
	media := []string{}
	rollback := func() {
		for i := len(media) - 1; i >= 0; i-- {
			if cerr := vbox.CloseMedium(context.Background(), vboxExe, media[i], true); cerr != nil {
				out.Write("stderr", "Rollback of "+media[i]+" failed: "+cerr.Error()+"\n")
			}
			// The rollback deletes what this step created + stamped — the
			// sidecar stamp (when the property write fell back) goes with it.
			removeMediumSidecar(media[i])
		}
	}

	// Typed disk spec re-validation at the RENDERED document (Mark's word,
	// sync 2026-07-17 — the ZERO-inference model): the packaged-render path
	// can emit disks the HTTP pre-flight never saw, so the same frozen
	// strings gate here before any medium materializes. Warnings narrate —
	// they never fail a build.
	diskProblems, diskWarnings := ValidateDisks(disks, settings)
	for _, warning := range diskWarnings {
		out.Write("stderr", "WARNING: "+warning+"\n")
	}
	if len(diskProblems) > 0 {
		for _, problem := range diskProblems {
			out.Write("stderr", problem+"\n")
		}
		return errors.New(diskProblems[0])
	}

	// Boot medium — disks.boot.type is the ONLY dispatcher (the typed disk
	// spec; the old presence-dispatch ladder died with it):
	//   template → clone settings.box's image, grow to boot.size, stamp
	//   image    → attach an EXISTING file AS-IS (existence + in-use
	//              pre-checked; never created/deleted/resized, never stamped)
	//   blank    → create a fresh VDI (sparse by default), stamp
	//   none     → DISKLESS — no boot medium at all (PXE/manual)
	// An ABSENT disks.boot is the spelled default: template when settings.box
	// is present, none otherwise — exactly the old box/diskless behavior.
	e.taskProgress(task, 10, "preparing_storage")
	boot := mapOr(disks["boot"])
	bootPath := ""
	boxRef := stringOr(settings["box"], "")
	switch EffectiveBootType(disks, settings) {
	case DiskTypeImage:
		bootPath = stringOr(boot["path"], "")
		if _, serr := os.Stat(bootPath); serr != nil {
			return errors.New("disks.boot.path " + bootPath + " does not exist on this host")
		}
		// In-use pre-check: a medium another machine holds is refused unless
		// the entry carries force: true (the frozen string names the holder).
		if force, _ := boot["force"].(bool); force {
			out.Write("stdout", "force: true — skipping the in-use pre-check for "+bootPath+"\n")
		} else {
			holder, herr := mediumHolder(ctx, vboxExe, bootPath, task.MachineName)
			if herr != nil {
				return herr
			}
			if holder != "" {
				return errors.New("disks.boot.path " + bootPath + " is attached to " + holder +
					" (set force: true to attach anyway)")
			}
		}
		out.Write("stdout", "Attaching existing boot medium "+bootPath+" (image — attached as-is, never ours to delete)\n")

	case DiskTypeTemplate:
		org, box, ok := strings.Cut(boxRef, "/")
		if !ok || org == "" || box == "" {
			return errors.New(`settings.box must be "organization/box-name"`)
		}
		template, terr := e.store.FindTemplate(ctx, org, box,
			stringOr(settings["box_version"], "latest"), TemplateProvider,
			stringOr(settings["box_arch"], "amd64"))
		if terr != nil {
			return fmt.Errorf("template %s/%s: %w (download it first — POST /templates/pull or let create chain it)", org, box, terr)
		}
		e.taskProgress(task, 30, "importing_template")
		if stringOr(boot["clone_strategy"], CloneStrategyCopy) == CloneStrategyClone {
			basePath := filepath.Join(filepath.Dir(template.DiskPath), cloneBaseName)
			if _, serr := os.Stat(basePath); serr != nil {
				e.clearStaleSourceRegistration(ctx, vboxExe, basePath, out)
				e.clearStaleSourceRegistration(ctx, vboxExe, template.DiskPath, out)
				out.Write("stdout", "Creating the shared clone base "+basePath+" (one-time full copy of "+template.DiskPath+")\n")
				if cerr := vbox.CloneMedium(ctx, vboxExe, template.DiskPath, basePath, "VDI"); cerr != nil {
					rollback()
					return cerr
				}
				if cerr := vbox.CloseMedium(ctx, vboxExe, template.DiskPath, false); cerr != nil {
					out.Write("stderr", "Releasing the template from the media registry failed (harmless when unregistered): "+cerr.Error()+"\n")
				}
				if perr := stampMedium(ctx, vboxExe, basePath, DiskTypeTemplate, out); perr != nil {
					rollback()
					return perr
				}
			}
			mediumType, terr2 := vbox.MediumType(ctx, vboxExe, basePath)
			if terr2 != nil {
				rollback()
				return terr2
			}
			if mediumType != "multiattach" {
				if merr := vbox.SetMediumType(ctx, vboxExe, basePath, "multiattach"); merr != nil {
					rollback()
					return fmt.Errorf("clone base %s could not be made multiattach: %w", basePath, merr)
				}
			}
			e.sweepOrphanCloneChildren(ctx, vboxExe, basePath, out)
			bootPath = basePath
			output.BootdiskMultiattach = true
			out.Write("stdout", "Boot links from the shared clone base (differencing disk created at attach)\n")
		} else {
			bootDir, derr := diskDirectory(boot, workdir, "disks.boot")
			if derr != nil {
				return derr
			}
			// The cloned file takes the entry's volume_name (zoneweaver names the
			// cloned zvol by it — the native mirror); absent = the spelled "boot"
			// default. The template's own format keeps its extension.
			bootPath = filepath.Join(bootDir,
				stringOr(boot["volume_name"], "boot")+filepath.Ext(template.DiskPath))
			clearStaleMedium(ctx, vboxExe, bootPath, out)
			e.clearStaleSourceRegistration(ctx, vboxExe, template.DiskPath, out)
			out.Write("stdout", "Cloning template "+template.DiskPath+" → "+bootPath+"\n")
			if cerr := vbox.CloneMedium(ctx, vboxExe, template.DiskPath, bootPath, ""); cerr != nil {
				rollback()
				return cerr
			}
			// Release the SOURCE's fresh registration immediately: clonemedium
			// registers the source, and a lingering entry goes STALE — packer's
			// stream-optimized VMDKs never take the UUID VirtualBox assigns, so
			// the NEXT clone dies on an E_FAIL UUID mismatch (Mark's live failure,
			// 2026-07-17). Failures narrate; the clone already succeeded.
			if cerr := vbox.CloseMedium(ctx, vboxExe, template.DiskPath, false); cerr != nil {
				out.Write("stderr", "Releasing the template from the media registry failed (harmless when unregistered): "+cerr.Error()+"\n")
			}
			media = append(media, bootPath)
			// Provenance stamp at materialization (property-first, sidecar
			// fallback): the delete flow destroys stamped media and preserves
			// everything else.
			if perr := stampMedium(ctx, vboxExe, bootPath, DiskTypeTemplate, out); perr != nil {
				rollback()
				return perr
			}
			if sizeMB := sizeToMB(boot["size"]); sizeMB > 0 {
				if rerr := vbox.ResizeMedium(ctx, vboxExe, bootPath, sizeMB); rerr != nil {
					out.Write("stderr", "Boot volume resize failed (continuing with template size): "+rerr.Error()+"\n")
				}
			}
		}

	case DiskTypeBlank:
		e.taskProgress(task, 30, "creating_boot_volume")
		name := stringOr(boot["volume_name"], "boot")
		bootDir, derr := diskDirectory(boot, workdir, "disks.boot")
		if derr != nil {
			return derr
		}
		bootPath = filepath.Join(bootDir, name+".vdi")
		sparse := true
		if v, bok := boot["sparse"].(bool); bok {
			sparse = v
		}
		clearStaleMedium(ctx, vboxExe, bootPath, out)
		out.Write("stdout", fmt.Sprintf("Creating blank boot volume %s (%d MB)\n",
			bootPath, sizeToMB(boot["size"])))
		if cerr := vbox.CreateMedium(ctx, vboxExe, bootPath, sizeToMB(boot["size"]), sparse); cerr != nil {
			rollback()
			return cerr
		}
		media = append(media, bootPath)
		if perr := stampMedium(ctx, vboxExe, bootPath, DiskTypeBlank, out); perr != nil {
			rollback()
			return perr
		}

	case DiskTypeNone:
		out.Write("stdout", "disks.boot.type none — DISKLESS machine (attach media later via modify)\n")

	default:
		// ValidateDisks refused every invalid/missing type above — defensive.
		return errors.New("disks.boot.type is required when disks.boot is present (template|image|blank|none)")
	}

	e.taskProgress(task, 60, "creating_additional_disks")
	disksDir := filepath.Join(workdir, "disks")
	for i, entry := range listOr(disks["additional_disks"]) {
		disk := mapOr(entry)
		// type is the dispatcher here too (image|blank — ValidateDisks
		// refused everything else above).
		switch stringOr(disk["type"], "") {
		case DiskTypeImage:
			// Attached by the config phase AS-IS — never created, stamped, or
			// rolled back here. Existence + in-use pre-checks mirror boot's
			// with the 1-based entry prefix.
			existing := stringOr(disk["path"], "")
			label := "disks.additional_disks[" + strconv.Itoa(i+1) + "].path " + existing
			if _, serr := os.Stat(existing); serr != nil {
				rollback()
				return errors.New(label + " does not exist on this host")
			}
			if force, _ := disk["force"].(bool); force {
				out.Write("stdout", "force: true — skipping the in-use pre-check for "+existing+"\n")
			} else {
				holder, herr := mediumHolder(ctx, vboxExe, existing, task.MachineName)
				if herr != nil {
					rollback()
					return herr
				}
				if holder != "" {
					rollback()
					return errors.New(label + " is attached to " + holder + " (set force: true to attach anyway)")
				}
			}
			out.Write("stdout", "Additional disk uses existing medium "+existing+"\n")

		case DiskTypeBlank:
			name := stringOr(disk["volume_name"], fmt.Sprintf("disk%d", i+1))
			sizeMB := sizeToMB(disk["size"])
			targetDir, derr := diskDirectory(disk,
				disksDir, "disks.additional_disks["+strconv.Itoa(i+1)+"]")
			if derr != nil {
				rollback()
				return derr
			}
			if targetDir == disksDir {
				// Only the DEFAULT location is agent-created; a custom
				// directory must already exist (diskDirectory checked).
				if merr := os.MkdirAll(disksDir, 0o750); merr != nil {
					rollback()
					return merr
				}
			}
			diskPath := filepath.Join(targetDir, name+".vdi")
			sparse := true
			if v, bok := disk["sparse"].(bool); bok {
				sparse = v
			}
			clearStaleMedium(ctx, vboxExe, diskPath, out)
			out.Write("stdout", fmt.Sprintf("Creating %s (%d MB)\n", diskPath, sizeMB))
			if cerr := vbox.CreateMedium(ctx, vboxExe, diskPath, sizeMB, sparse); cerr != nil {
				rollback()
				return cerr
			}
			media = append(media, diskPath)
			if perr := stampMedium(ctx, vboxExe, diskPath, DiskTypeBlank, out); perr != nil {
				rollback()
				return perr
			}
		}
	}

	output.BootdiskPath = bootPath
	output.MediaCreated = media
	if rerr := e.recordOutput(ctx, task, meta.Spec, output); rerr != nil {
		rollback()
		return rerr
	}
	e.taskProgress(task, 100, "completed")
	return nil
}

// createStorageUTM is machine_create_storage's UTM branch: this hypervisor
// materializes no media — the template's box.utm bundle imports WHOLE at the
// config step (utm.Import copies it into UTM's own storage), so this step
// only resolves the template and verifies the bundle exists. BootdiskPath is
// REUSED to carry the bundle directory forward (no boot medium exists to
// name); no media list, no stamps, no rollback.
func (e *executors) createStorageUTM(ctx context.Context, task *tasks.Task, spec *Spec,
	output *createExecutionOutput, settings map[string]any, out *tasks.OutputWriter,
) error {
	e.taskProgress(task, 10, "preparing_storage")
	// prepare's materialize normally creates the working directory; a
	// provisioner-less create has no prepare, so ensure it (idempotent) —
	// finalize records Home pointing at it either way.
	if merr := os.MkdirAll(e.machineWorkdir(task.MachineName), 0o750); merr != nil {
		return merr
	}
	boxRef := stringOr(settings["box"], "")
	org, box, ok := strings.Cut(boxRef, "/")
	if !ok || org == "" || box == "" {
		return errors.New(`settings.box must be "organization/box-name"`)
	}
	template, terr := e.store.FindTemplate(ctx, org, box,
		stringOr(settings["box_version"], "latest"), TemplateProviderUTM,
		stringOr(settings["box_arch"], "amd64"))
	if terr != nil {
		return fmt.Errorf("template %s/%s: %w (download it first — POST /templates/pull or let create chain it)", org, box, terr)
	}
	info, serr := os.Stat(template.DiskPath)
	if serr != nil || !info.IsDir() {
		return errors.New("template " + boxRef + " carries no box.utm bundle directory at " + template.DiskPath)
	}
	out.Write("stdout", "UTM template bundle "+template.DiskPath+" (imported whole at the config step)\n")
	output.BootdiskPath = template.DiskPath
	if rerr := e.recordOutput(ctx, task, spec, output); rerr != nil {
		return rerr
	}
	e.taskProgress(task, 100, "completed")
	return nil
}
