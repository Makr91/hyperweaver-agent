package server

// USB passthrough surface (Mark's verb-survey go 2026-07-12): the host
// device list, live attach/detach into running machines, and persistent
// capture filters.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// handleListHostUSB serves GET /system/usb — the host's USB devices
// (VBoxManage list usbhost), the attach/filter pickers' feed.
func (s *Server) handleListHostUSB(w http.ResponseWriter, r *http.Request) {
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	devices, err := vbox.ListUSBHost(r.Context(), exe)
	if err != nil {
		slog.Error("list host usb", "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list host USB devices")
		return
	}
	writeJSON(w, map[string]any{"devices": devices, "total": len(devices)})
}

// handleUSBAttach serves POST /machines/{machineName}/usb/attach — hot-plug
// a host device (by UUID or address) into the running machine. The machine
// needs a USB controller (hardware.usb at create/modify).
func (s *Server) handleUSBAttach(w http.ResponseWriter, r *http.Request) {
	s.runUSBVerb(w, r, vbox.USBAttach, "attach")
}

// handleUSBDetach serves POST /machines/{machineName}/usb/detach.
func (s *Server) handleUSBDetach(w http.ResponseWriter, r *http.Request) {
	s.runUSBVerb(w, r, vbox.USBDetach, "detach")
}

// runUSBVerb is the shared attach/detach shape: running machine, body
// {device: uuid|address}, synchronous controlvm verb.
func (s *Server) runUSBVerb(w http.ResponseWriter, r *http.Request,
	verb func(ctx context.Context, vboxManage, name, device string) error, action string,
) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body struct {
		Device string `json:"device"`
	}
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Device == "" {
		taskError(w, http.StatusBadRequest, "device is required (a UUID or address from GET /system/usb)")
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if liveMachineStatus(r.Context(), machine) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "USB "+action+" needs a running machine")
		return
	}
	if err := verb(r.Context(), exe, machine.VBoxTarget(), body.Device); err != nil {
		slog.Error("usb "+action, "machine", machine.Name, "device", body.Device, "error", err)
		taskError(w, http.StatusInternalServerError, "USB "+action+" failed: "+err.Error())
		return
	}
	slog.Info("usb "+action, "machine", machine.Name, "device", body.Device,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"device":       body.Device,
		"message":      "USB " + action + " completed",
	})
}

// usbFilterKey matches machinereadable's USBFilter<Field><N> keys.
var usbFilterKey = regexp.MustCompile(`^USBFilter([A-Za-z]+)(\d+)$`)

// usbFilterEntry is one persistent filter as the wire reports it.
type usbFilterEntry struct {
	// Index is usbfilter remove's 0-based position.
	Index        int    `json:"index"`
	Name         string `json:"name"`
	Active       bool   `json:"active"`
	VendorID     string `json:"vendor_id,omitempty"`
	ProductID    string `json:"product_id,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
}

// machineUSBFilters parses the machine's filters from the live
// machinereadable view (USBFilter* keys, 1-based slots → 0-based indices).
func (s *Server) machineUSBFilters(ctx context.Context, exe string, machine *machines.Machine) ([]usbFilterEntry, error) {
	info, err := vbox.ShowVMInfo(ctx, exe, machine.VBoxTarget())
	if err != nil {
		return nil, err
	}
	bySlot := map[int]*usbFilterEntry{}
	for key, value := range info.Raw {
		match := usbFilterKey.FindStringSubmatch(key)
		if match == nil {
			continue
		}
		slot, serr := strconv.Atoi(match[2])
		if serr != nil {
			continue
		}
		entry := bySlot[slot]
		if entry == nil {
			entry = &usbFilterEntry{Index: slot - 1}
			bySlot[slot] = entry
		}
		switch match[1] {
		case "Name":
			entry.Name = value
		case "Active":
			entry.Active = value == "yes" || value == "true"
		case "VendorId":
			entry.VendorID = value
		case "ProductId":
			entry.ProductID = value
		case "Manufacturer":
			entry.Manufacturer = value
		case "Product":
			entry.Product = value
		case "SerialNumber":
			entry.SerialNumber = value
		}
	}
	filters := make([]usbFilterEntry, 0, len(bySlot))
	for _, entry := range bySlot {
		filters = append(filters, *entry)
	}
	sort.Slice(filters, func(i, j int) bool { return filters[i].Index < filters[j].Index })
	return filters, nil
}

// handleListUSBFilters serves GET /machines/{machineName}/usb/filters.
func (s *Server) handleListUSBFilters(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	filters, err := s.machineUSBFilters(r.Context(), exe, machine)
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("list usb filters", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to list USB filters")
		return
	}
	writeJSON(w, map[string]any{
		"machine_name": machine.Name,
		"filters":      filters,
		"total":        len(filters),
	})
}

// handleAddUSBFilter serves POST /machines/{machineName}/usb/filters —
// append a persistent capture filter (empty match fields match anything).
func (s *Server) handleAddUSBFilter(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	var body vbox.USBFilterSpec
	if err := decodeBody(r, &body); err != nil {
		taskError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}
	if body.Name == "" {
		taskError(w, http.StatusBadRequest, "name is required")
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	existing, err := s.machineUSBFilters(r.Context(), exe, machine)
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("count usb filters", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to add USB filter")
		return
	}
	index := len(existing)
	if aerr := vbox.USBFilterAdd(r.Context(), exe, machine.VBoxTarget(), index, &body); aerr != nil {
		slog.Error("add usb filter", "machine", machine.Name, "error", aerr)
		taskError(w, http.StatusInternalServerError, "Failed to add USB filter: "+aerr.Error())
		return
	}
	slog.Info("usb filter added", "machine", machine.Name, "filter", body.Name,
		"by", auth.FromContext(r.Context()).Name)
	writeJSONStatus(w, http.StatusCreated, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"index":        index,
		"name":         body.Name,
		"message":      "USB filter added",
	})
}

// handleRemoveUSBFilter serves DELETE
// /machines/{machineName}/usb/filters/{filterIndex}.
func (s *Server) handleRemoveUSBFilter(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	index, err := strconv.Atoi(r.PathValue("filterIndex"))
	if err != nil || index < 0 {
		taskError(w, http.StatusBadRequest, "filterIndex must be a non-negative integer")
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	if rerr := vbox.USBFilterRemove(r.Context(), exe, machine.VBoxTarget(), index); rerr != nil {
		slog.Error("remove usb filter", "machine", machine.Name, "index", index, "error", rerr)
		taskError(w, http.StatusInternalServerError, "Failed to remove USB filter: "+rerr.Error())
		return
	}
	slog.Info("usb filter removed", "machine", machine.Name, "index", index,
		"by", auth.FromContext(r.Context()).Name)
	writeJSON(w, map[string]any{
		"success":      true,
		"machine_name": machine.Name,
		"index":        index,
		"message":      "USB filter removed",
	})
}
