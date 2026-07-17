package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/Makr91/hyperweaver-agent/internal/hostinfo"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// Pre-flight resource validation on create/clone/modify — the base's
// lib/resourcevalidation family in VirtualBox terms: disk free where the
// media land (the machines root's volume replaces the ZFS pool), host RAM
// (no ARC on this platform), and CPU overcommit against physical cores.
// Failing checks answer 400 {error: "Insufficient resources", details[]};
// passing checks may annotate resource_warnings[] on the success response.
// Probe failures never block an operation — they warn and pass (the base
// logs-and-continues the same way).

const mib = int64(1024 * 1024)

// int64Clamped converts an unsigned byte count to int64, capping at MaxInt64
// so the conversion can never overflow.
func int64Clamped(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// resourceIssue is one error or warning entry (the base's details[] shape).
type resourceIssue = map[string]any

// committedTotals sums every registered machine's CONFIGURED allocations from
// its stored spec (the base sums zone configurations). runningOnly serves the
// "actual" CPU strategy; exclude drops the machine being modified.
func (s *Server) committedTotals(ctx context.Context, exclude string, runningOnly bool) (memoryBytes, vcpus, storageBytes int64) {
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		slog.Warn("resource validation: list machines failed", "error", err)
		return 0, 0, 0
	}
	for _, machine := range list {
		if machine.Name == exclude || len(machine.Spec) == 0 {
			continue
		}
		if runningOnly && machine.Status != machines.StatusRunning {
			continue
		}
		spec, perr := machines.ParseSpec(machine)
		if perr != nil {
			continue
		}
		memoryBytes += machines.MemoryToMB(spec.Settings["memory"]) * mib
		// VCPUCount, not DocInt (converged v2, sync 2026-07-17): committed
		// sums must count a float-string "4.0" as 4, never the default.
		vcpus += machines.VCPUCount(spec.Settings["vcpus"], 2)
		storageBytes += requestedStorageBytes(spec.Disks)
	}
	return memoryBytes, vcpus, storageBytes
}

// requestedStorageBytes sums the NEW media a disks document asks for: the
// boot volume (existing-path attaches consume nothing new) and every
// additional disk without a path. ISO attaches consume nothing.
func requestedStorageBytes(disks map[string]any) int64 {
	if len(disks) == 0 {
		return 0
	}
	total := int64(0)
	boot, _ := disks["boot"].(map[string]any)
	if machines.DocString(boot["path"], "") == "" {
		total += machines.SizeToMB(boot["size"]) * mib
	}
	if additional, ok := disks["additional_disks"].([]any); ok {
		for _, entry := range additional {
			d, _ := entry.(map[string]any)
			if machines.DocString(d["path"], "") != "" {
				continue
			}
			total += machines.SizeToMB(d["size"]) * mib
		}
	}
	return total
}

func formatBytes(b int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(b)
	i := 0
	for value >= 1024 && i < len(units)-1 {
		value /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", value, units[i])
}

func roundPct(p float64) float64 {
	return math.Round(p*100) / 100
}

// thresholdWarning annotates warn/critical utilization (never blocks).
func thresholdWarning(resource string, projectedPct, warning, critical float64, detail string) resourceIssue {
	var level string
	var threshold float64
	switch {
	case critical > 0 && projectedPct > critical:
		level, threshold = "critical", critical
	case warning > 0 && projectedPct > warning:
		level, threshold = "warning", warning
	default:
		return nil
	}
	return resourceIssue{
		"resource":          resource,
		"level":             level,
		"message":           fmt.Sprintf("%s will be %.2f%% utilized after this operation (%s threshold: %.0f%%)", detail, roundPct(projectedPct), level, threshold),
		"projected_percent": roundPct(projectedPct),
	}
}

// validateStorage checks requested bytes against the machines root's volume.
func (s *Server) validateStorage(ctx context.Context, requested int64, exclude string) (errs, warns []resourceIssue) {
	cfg := s.cfg.Machines.ResourceValidation.Storage
	root, err := s.cfg.MachinesDir()
	if err != nil {
		return nil, nil
	}
	usage, err := disk.UsageWithContext(ctx, root)
	if err != nil {
		slog.Warn("resource validation: disk usage probe failed", "path", root, "error", err)
		return nil, nil
	}
	total := int64Clamped(usage.Total)
	free := int64Clamped(usage.Free)
	if total <= 0 {
		return nil, nil
	}

	var projectedPct float64
	if strings.EqualFold(cfg.Strategy, "committed") {
		_, _, committed := s.committedTotals(ctx, exclude, false)
		projected := committed + requested
		projectedPct = float64(projected) / float64(total) * 100
		if projected > total {
			return []resourceIssue{{
				"resource":           "storage",
				"volume":             root,
				"strategy":           "committed",
				"message":            fmt.Sprintf("Requested %s would exceed volume capacity (%s committed + %s requested > %s total)", formatBytes(requested), formatBytes(committed), formatBytes(requested), formatBytes(total)),
				"volume_total_bytes": total,
				"committed_bytes":    committed,
				"requested_bytes":    requested,
				"projected_percent":  roundPct(projectedPct),
			}}, nil
		}
	} else {
		projectedPct = float64(total-free+requested) / float64(total) * 100
		if requested > free {
			return []resourceIssue{{
				"resource":           "storage",
				"volume":             root,
				"strategy":           "actual",
				"message":            fmt.Sprintf("Requested %s exceeds available space on %s (%s free)", formatBytes(requested), root, formatBytes(free)),
				"volume_total_bytes": total,
				"volume_free_bytes":  free,
				"requested_bytes":    requested,
				"projected_percent":  roundPct(projectedPct),
			}}, nil
		}
	}
	if w := thresholdWarning("storage", projectedPct, cfg.Thresholds.Warning, cfg.Thresholds.Critical,
		"Volume "+root); w != nil {
		warns = append(warns, w)
	}
	return nil, warns
}

// validateMemory checks requested RAM against host memory.
func (s *Server) validateMemory(ctx context.Context, requested int64, exclude string) (errs, warns []resourceIssue) {
	cfg := s.cfg.Machines.ResourceValidation.Memory
	hostTotalU, hostFreeU := hostinfo.MemoryStatus()
	hostTotal := int64Clamped(hostTotalU)
	hostFree := int64Clamped(hostFreeU)
	if hostTotal <= 0 {
		return nil, nil
	}

	var projectedPct float64
	if strings.EqualFold(cfg.Strategy, "actual") {
		projectedPct = float64(hostTotal-hostFree+requested) / float64(hostTotal) * 100
		if requested > hostFree {
			return []resourceIssue{{
				"resource":          "memory",
				"strategy":          "actual",
				"message":           fmt.Sprintf("Requested %s exceeds available host memory (%s free)", formatBytes(requested), formatBytes(hostFree)),
				"host_total_bytes":  hostTotal,
				"host_free_bytes":   hostFree,
				"requested_bytes":   requested,
				"projected_percent": roundPct(projectedPct),
			}}, nil
		}
	} else {
		committed, _, _ := s.committedTotals(ctx, exclude, false)
		projected := committed + requested
		projectedPct = float64(projected) / float64(hostTotal) * 100
		if projected > hostTotal {
			return []resourceIssue{{
				"resource":          "memory",
				"strategy":          "committed",
				"message":           fmt.Sprintf("Requested %s would exceed host memory (%s committed + %s requested > %s total)", formatBytes(requested), formatBytes(committed), formatBytes(requested), formatBytes(hostTotal)),
				"host_total_bytes":  hostTotal,
				"committed_bytes":   committed,
				"requested_bytes":   requested,
				"projected_percent": roundPct(projectedPct),
			}}, nil
		}
	}
	if w := thresholdWarning("memory", projectedPct, cfg.Thresholds.Warning, cfg.Thresholds.Critical,
		"Host memory"); w != nil {
		warns = append(warns, w)
	}
	return nil, warns
}

// validateCPU checks requested vCPUs against the overcommit hard limit.
func (s *Server) validateCPU(ctx context.Context, requested int64, exclude string) (errs, warns []resourceIssue) {
	cfg := s.cfg.Machines.ResourceValidation.CPU
	hostCPUs := int64(runtime.NumCPU())
	if hostCPUs <= 0 || requested <= 0 {
		return nil, nil
	}
	runningOnly := strings.EqualFold(cfg.Strategy, "actual")
	_, committed, _ := s.committedTotals(ctx, exclude, runningOnly)
	projected := committed + requested
	projectedPct := float64(projected) / float64(hostCPUs) * 100

	if cfg.HardLimit > 0 && projectedPct > cfg.HardLimit {
		return []resourceIssue{{
			"resource":           "cpu",
			"strategy":           cfg.Strategy,
			"message":            fmt.Sprintf("Requested %d vCPUs would exceed overcommit limit (%d allocated + %d requested = %d total vCPUs, %.0f%% of %d physical cores, limit: %.0f%%)", requested, committed, requested, projected, projectedPct, hostCPUs, cfg.HardLimit),
			"host_cpu_count":     hostCPUs,
			"committed_vcpus":    committed,
			"requested_vcpus":    requested,
			"projected_vcpus":    projected,
			"projected_percent":  roundPct(projectedPct),
			"hard_limit_percent": cfg.HardLimit,
		}}, nil
	}
	if w := thresholdWarning("cpu", projectedPct, cfg.Thresholds.Warning, cfg.Thresholds.Critical,
		fmt.Sprintf("Host vCPU allocation (%d physical cores, %d allocated vCPUs)", hostCPUs, projected)); w != nil {
		warns = append(warns, w)
	}
	return nil, warns
}

// validateCreationResources runs the enabled validators against a creation
// document (settings + disks) — the base's validateZoneCreationResources.
func (s *Server) validateCreationResources(ctx context.Context, document map[string]any) (errs, warns []resourceIssue) {
	rv := s.cfg.Machines.ResourceValidation
	if !rv.Enabled {
		return nil, nil
	}
	settings, _ := document["settings"].(map[string]any)
	disks, _ := document["disks"].(map[string]any)

	if rv.Storage.Enabled {
		if requested := requestedStorageBytes(disks); requested > 0 {
			e, w := s.validateStorage(ctx, requested, "")
			errs, warns = append(errs, e...), append(warns, w...)
		}
	}
	if rv.Memory.Enabled {
		if requested := machines.MemoryToMB(settings["memory"]) * mib; requested > 0 {
			e, w := s.validateMemory(ctx, requested, "")
			errs, warns = append(errs, e...), append(warns, w...)
		}
	}
	if rv.CPU.Enabled {
		// VCPUCount (converged v2, sync 2026-07-17): the guard-passed value's
		// canonical integer, never a ParseInt fallback.
		if requested := machines.VCPUCount(settings["vcpus"], 0); requested > 0 {
			e, w := s.validateCPU(ctx, requested, "")
			errs, warns = append(errs, e...), append(warns, w...)
		}
	}
	return errs, warns
}

// validateModificationResources checks only the fields a modify body changes
// (add_disks → storage, ram → memory, vcpus → CPU), excluding the machine
// itself from committed sums — validateZoneModificationResources.
func (s *Server) validateModificationResources(ctx context.Context, body map[string]any, machineName string) (errs, warns []resourceIssue) {
	rv := s.cfg.Machines.ResourceValidation
	if !rv.Enabled {
		return nil, nil
	}
	if rv.Storage.Enabled {
		if addDisks, ok := body["add_disks"].([]any); ok && len(addDisks) > 0 {
			if requested := requestedStorageBytes(map[string]any{"additional_disks": addDisks}); requested > 0 {
				e, w := s.validateStorage(ctx, requested, machineName)
				errs, warns = append(errs, e...), append(warns, w...)
			}
		}
	}
	if rv.Memory.Enabled {
		if ram, ok := body["ram"]; ok {
			if requested := machines.MemoryToMB(ram) * mib; requested > 0 {
				e, w := s.validateMemory(ctx, requested, machineName)
				errs, warns = append(errs, e...), append(warns, w...)
			}
		}
	}
	if rv.CPU.Enabled {
		if vcpus, ok := body["vcpus"]; ok {
			// VCPUCount (converged v2, sync 2026-07-17) — same normalization
			// as the create-side count reads.
			if requested := machines.VCPUCount(vcpus, 0); requested > 0 {
				e, w := s.validateCPU(ctx, requested, machineName)
				errs, warns = append(errs, e...), append(warns, w...)
			}
		}
	}
	return errs, warns
}

// insufficientResources writes the base's 400 rejection shape.
func insufficientResources(w http.ResponseWriter, details []resourceIssue) {
	writeJSONStatus(w, http.StatusBadRequest, map[string]any{
		"error":   "Insufficient resources",
		"details": details,
	})
}

// writeJSONStatus writes a JSON payload with an explicit status code.
func writeJSONStatus(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Error("write json response", "error", err)
	}
}
