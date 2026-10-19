package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/safepath"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// validateSpec checks the creation spec: the provisioner reference is
// OPTIONAL (the base's provisioner-free create — Mark's ruling 2026-07-07)
// and validated against the registry only when given; hostname and domain are
// required (the name derives from them, an absent domain taking
// machines.default_domain), the typed disk spec must hold, role names must be
// usable, sync_method must be valid. diskWarnings carry the typed-disk never-refuse rows (bhyve
// vocabulary keys, an unused settings.box) for the create response's
// resource_warnings.
func (s *Server) validateSpec(w http.ResponseWriter, spec *machines.Spec) (ok bool, diskWarnings []string) {
	if (spec.Provisioner.Name == "") != (spec.Provisioner.Version == "") {
		taskError(w, http.StatusBadRequest,
			"provisioner needs both name and version — or neither: provisioning is optional")
		return false, nil
	}
	if spec.HasProvisioner() {
		version, err := s.provisioners.GetVersion(spec.Provisioner.Name, spec.Provisioner.Version)
		if err != nil {
			if errors.Is(err, provisioner.ErrNotFound) || errors.Is(err, provisioner.ErrVersionNotFound) {
				taskError(w, http.StatusBadRequest,
					"provisioner "+spec.Provisioner.Name+"/"+spec.Provisioner.Version+" is not in the registry")
				return false, nil
			}
			slog.Error("resolve provisioner for machine spec", "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to resolve provisioner")
			return false, nil
		}
		// Authoritative pre-render answer validation (Field DSL, design §3.1):
		// the ruled wire is a 422 whose body IS the {FIELD: message} map.
		problems, derr := provisioner.ValidateVersionAnswers(version, spec.Roles,
			spec.Properties, nil, false)
		if derr != nil {
			taskError(w, http.StatusBadRequest, derr.Error())
			return false, nil
		}
		if len(problems) > 0 {
			writeJSONStatus(w, http.StatusUnprocessableEntity, problems)
			return false, nil
		}
	}
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	hostname, _ := spec.Settings["hostname"].(string)
	domain, _ := spec.Settings["domain"].(string)
	if domain == "" && s.cfg.Machines.DefaultDomain != "" {
		domain = s.cfg.Machines.DefaultDomain
		spec.Settings["domain"] = domain
	}
	if hostname == "" || domain == "" {
		taskError(w, http.StatusBadRequest,
			"Missing required parameters: settings.hostname and settings.domain are required")
		return false, nil
	}
	// consoleport pre-flight (converged, sync 2026-07-17): when the request's
	// settings carry consoleport it must be an integer 1025-65535 (number or
	// numeric string) — the value feeds VRDE's TCP/Ports, and an out-of-range
	// value otherwise dies mid-chain as a cryptic modifyvm E_INVALIDARG. An
	// ABSENT consoleport is fine; the render-time default is the executor
	// guard's business (create_exec.go).
	if value, ok := spec.Settings["consoleport"]; ok {
		if problem := machines.ConsolePortProblem(value); problem != "" {
			taskError(w, http.StatusBadRequest, problem)
			return false, nil
		}
	}
	// vcpus pre-flight (converged, sync 2026-07-17 — zoneweaver's proposal,
	// ACKED): a present settings.vcpus must be a whole number >= 1 (integral
	// floats like 2.0 pass — the 0.1.31 template renders them from wizard
	// integers). Absent keeps the default-2 behavior byte-identical; the
	// render-time value is the executor guard's business (create_exec.go).
	if value, ok := spec.Settings["vcpus"]; ok {
		if problem := machines.VCPUProblem(value); problem != "" {
			taskError(w, http.StatusBadRequest, problem)
			return false, nil
		}
	}
	// Typed disk spec pre-flight (Mark's word, sync 2026-07-17 — the
	// ZERO-inference model): disks.boot.type dispatches everything; the FIRST
	// frozen-string problem answers the 400, warnings ride the response's
	// resource_warnings. The rendered document re-validates at task time —
	// this gate covers the request's own disks.
	diskProblems, diskWarnings := machines.ValidateDisks(spec.Disks, spec.Settings)
	if len(diskProblems) > 0 {
		taskError(w, http.StatusBadRequest, diskProblems[0])
		return false, nil
	}
	// Per-machine hypervisor selection (phase 3): ""/virtualbox = VirtualBox,
	// utm = UTM — anything else refuses with the value verbatim. utm gates on
	// a macOS agent host and, until the other boot types land, on the
	// template boot type (create = box.utm bundle import).
	switch spec.Hypervisor {
	case "", machines.HypervisorVirtualBox, machines.HypervisorUTM:
	default:
		taskError(w, http.StatusBadRequest,
			"hypervisor "+spec.Hypervisor+" is not a valid hypervisor (virtualbox|utm)")
		return false, nil
	}
	if spec.Hypervisor == machines.HypervisorUTM {
		if runtime.GOOS != "darwin" {
			taskError(w, http.StatusBadRequest, "hypervisor utm requires a macOS agent host")
			return false, nil
		}
		if effective := machines.EffectiveBootType(spec.Disks, spec.Settings); effective != machines.DiskTypeTemplate {
			taskError(w, http.StatusBadRequest,
				"hypervisor utm builds from a box (settings.box) — disks.boot.type "+effective+" is not yet supported on utm")
			return false, nil
		}
	}
	for i := range spec.Roles {
		if !provisioner.ValidName(spec.Roles[i].Name) {
			taskError(w, http.StatusBadRequest, "role name "+spec.Roles[i].Name+" is not usable")
			return false, nil
		}
	}
	switch spec.SyncMethod {
	case "", machines.SyncRsync, machines.SyncSCP:
	default:
		taskError(w, http.StatusBadRequest, "sync_method must be rsync or scp")
		return false, nil
	}
	return true, diskWarnings
}

// chainWaitFor checks the wait_for task ids, chains each behind the one before it and answers the last, the task the create's first child waits on; nil with no ids.
func (s *Server) chainWaitFor(ctx context.Context, ids []string) (last *string, problem string) {
	previous := ""
	for i, id := range ids {
		task, err := s.tasks.Store().Get(ctx, id)
		if errors.Is(err, tasks.ErrNotFound) {
			return nil, "wait_for task " + id + " not found"
		}
		if err != nil {
			return nil, "Failed to read wait_for task " + id
		}
		switch task.Status {
		case tasks.StatusPending, tasks.StatusPrepared, tasks.StatusRunning:
		default:
			return nil, "wait_for task " + id + " is " + task.Status
		}
		if i > 0 {
			if derr := s.tasks.Store().SetDependsOn(ctx, id, previous); derr != nil {
				return nil, "Failed to chain wait_for task " + id
			}
		}
		previous = id
	}
	if previous == "" {
		return nil, ""
	}
	return &previous, ""
}

// diskWarningRows wraps the typed-disk warning strings into the create
// response's resource_warnings row shape (converged, sync 2026-07-17):
// {"resource": "disks", "message": ...}.
func diskWarningRows(warnings []string) []resourceIssue {
	rows := make([]resourceIssue, 0, len(warnings))
	for _, warning := range warnings {
		rows = append(rows, resourceIssue{"resource": "disks", "message": warning})
	}
	return rows
}

// workdirTaken reports whether another machine row claims the working
// directory the name sanitizes to.
func (s *Server) workdirTaken(ctx context.Context, machinesRoot, name string) (taken bool, home string, err error) {
	home, err = safepath.Under(machinesRoot, provisioner.MachineDirName(name))
	if err != nil {
		return false, "", err
	}
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		return false, "", err
	}
	for _, machine := range list {
		if machine.Home != nil && strings.EqualFold(*machine.Home, home) {
			return true, home, nil
		}
	}
	return false, home, nil
}
