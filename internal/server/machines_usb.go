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

// hostUSBResponse is GET /system/usb's answer: the host's USB device list.
type hostUSBResponse struct {
	Devices []vbox.USBDevice `json:"devices"`
	Total   int              `json:"total"`
}

// handleListHostUSB serves GET /system/usb — the host's USB devices
// (VBoxManage list usbhost), the attach/filter pickers' feed.
//
//	@Summary		List the host's USB devices
//	@Description	Minimum role: viewer. VBoxManage list usbhost — the attach and filter pickers' feed. state carries VirtualBox's capture view (Busy/Available/Captured/Unavailable).
//	@Tags			Machine Management
//	@Produce		json
//	@Success		200	{object}	hostUSBResponse	"Host USB devices"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/system/usb [get]
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
	writeJSON(w, hostUSBResponse{Devices: devices, Total: len(devices)})
}

// usbDeviceRequest is the attach/detach body: the host device to hot-plug.
type usbDeviceRequest struct {
	// Device UUID or address
	Device string `json:"device"`
}

// usbActionResponse is the attach/detach answer.
type usbActionResponse struct {
	Device      string `json:"device"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
	Success     bool   `json:"success"`
}

// handleUSBAttach serves POST /machines/{machineName}/usb/attach — hot-plug
// a host device (by UUID or address) into the running machine. The machine
// needs a USB controller (hardware.usb at create/modify).
//
//	@Summary		Attach a host USB device
//	@Description	Minimum role: operator. Synchronous controlvm usbattach — hot-plug a host device (by UUID or address from GET /system/usb) into the RUNNING machine. The machine needs a USB controller (hardware.usb.ohci/ehci/xhci at create or modify); VirtualBox's own error answers when it lacks one.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	usbDeviceRequest	true	"Host USB device to attach"
//	@Success		200	{object}	usbActionResponse	"Device attached ({success, machine_name, device, message})"
//	@Failure		400	{object}	taskErrorBody	"Missing device, or machine not running"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/usb/attach [post]
func (s *Server) handleUSBAttach(w http.ResponseWriter, r *http.Request) {
	s.runUSBVerb(w, r, vbox.USBAttach, "attach")
}

// handleUSBDetach serves POST /machines/{machineName}/usb/detach.
//
//	@Summary		Detach a USB device
//	@Description	Minimum role: operator. Synchronous controlvm usbdetach from the running machine.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	usbDeviceRequest	true	"Host USB device to detach"
//	@Success		200	{object}	usbActionResponse	"Device detached"
//	@Failure		400	{object}	taskErrorBody	"Missing device, or machine not running"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/usb/detach [post]
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
	var body usbDeviceRequest
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
	writeJSON(w, usbActionResponse{
		Success:     true,
		MachineName: machine.Name,
		Device:      body.Device,
		Message:     "USB " + action + " completed",
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

// usbFiltersResponse is GET /machines/{machineName}/usb/filters's answer.
type usbFiltersResponse struct {
	Filters     []usbFilterEntry `json:"filters"`
	MachineName string           `json:"machine_name"`
	Total       int              `json:"total"`
}

// handleListUSBFilters serves GET /machines/{machineName}/usb/filters.
//
//	@Summary		List USB capture filters
//	@Description	Minimum role: viewer. The machine's persistent filters from the live machinereadable view. index is usbfilter remove's 0-based position.
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	usbFiltersResponse	"Filters"
//	@Failure		404	{object}	taskErrorBody	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/usb/filters [get]
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
	writeJSON(w, usbFiltersResponse{
		MachineName: machine.Name,
		Filters:     filters,
		Total:       len(filters),
	})
}

// usbFilterAddResponse is POST /machines/{machineName}/usb/filters's answer.
type usbFilterAddResponse struct {
	Index       int    `json:"index"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
	Name        string `json:"name"`
	Success     bool   `json:"success"`
}

// handleAddUSBFilter serves POST /machines/{machineName}/usb/filters —
// append a persistent capture filter (empty match fields match anything).
//
//	@Summary		Add a USB capture filter
//	@Description	Minimum role: operator. Appends a persistent filter (usbfilter add): matching devices auto-capture into the machine at plug-in/boot. Empty match fields match anything. Works on running and powered-off machines.
//	@Tags			Machine Management
//	@Accept			json
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			request	body	vbox.USBFilterSpec	true	"USB capture filter to add"
//	@Success		201	{object}	usbFilterAddResponse	"Filter added ({success, machine_name, index, name, message})"
//	@Failure		400	{object}	taskErrorBody	"Missing name"
//	@Failure		404	{object}	taskErrorBody	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/usb/filters [post]
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
	writeJSONStatus(w, http.StatusCreated, usbFilterAddResponse{
		Success:     true,
		MachineName: machine.Name,
		Index:       index,
		Name:        body.Name,
		Message:     "USB filter added",
	})
}

// usbFilterRemoveResponse is the DELETE .../usb/filters/{filterIndex} answer.
type usbFilterRemoveResponse struct {
	Index       int    `json:"index"`
	MachineName string `json:"machine_name"`
	Message     string `json:"message"`
	Success     bool   `json:"success"`
}

// handleRemoveUSBFilter serves DELETE
// /machines/{machineName}/usb/filters/{filterIndex}.
//
//	@Summary		Remove a USB capture filter
//	@Description	Minimum role: operator. usbfilter remove by 0-based index (GET /usb/filters reports it).
//	@Tags			Machine Management
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			filterIndex	path	int	true	"Filter index (0-based)"
//	@Success		200	{object}	usbFilterRemoveResponse	"Filter removed"
//	@Failure		400	{object}	taskErrorBody	"Invalid index"
//	@Failure		404	{object}	taskErrorBody	"Machine not found"
//	@Failure		503	{object}	taskErrorBody	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/usb/filters/{filterIndex} [delete]
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
	writeJSON(w, usbFilterRemoveResponse{
		Success:     true,
		MachineName: machine.Name,
		Index:       index,
		Message:     "USB filter removed",
	})
}
