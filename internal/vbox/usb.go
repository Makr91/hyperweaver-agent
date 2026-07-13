package vbox

// USB passthrough verbs: the host device list, live attach/detach
// (controlvm), and persistent filters (usbfilter).

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// USBDevice is one `list usbhost` entry.
type USBDevice struct {
	UUID         string `json:"uuid"`
	VendorID     string `json:"vendor_id"`
	ProductID    string `json:"product_id"`
	Revision     string `json:"revision,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	Address      string `json:"address,omitempty"`
	State        string `json:"state,omitempty"`
}

// ListUSBHost parses `VBoxManage list usbhost` — blocks of `Key: value`
// lines, each device starting at a UUID: line.
func ListUSBHost(ctx context.Context, vboxManage string) ([]USBDevice, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "list", "usbhost")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage list usbhost: %w", err)
	}

	devices := []USBDevice{}
	var current *USBDevice
	for _, line := range strings.Split(string(out), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "UUID":
			devices = append(devices, USBDevice{UUID: value})
			current = &devices[len(devices)-1]
		case "VendorId":
			if current != nil {
				current.VendorID = value
			}
		case "ProductId":
			if current != nil {
				current.ProductID = value
			}
		case "Revision":
			if current != nil {
				current.Revision = value
			}
		case "Manufacturer":
			if current != nil {
				current.Manufacturer = value
			}
		case "Product":
			if current != nil {
				current.Product = value
			}
		case "SerialNumber":
			if current != nil {
				current.SerialNumber = value
			}
		case "Address":
			if current != nil {
				current.Address = value
			}
		case "Current State":
			if current != nil {
				current.State = value
			}
		}
	}
	return devices, nil
}

// USBAttach hot-plugs a host device into a running machine
// (`controlvm usbattach` — by UUID or address).
func USBAttach(ctx context.Context, vboxManage, name, device string) error {
	return runSimple(ctx, vboxManage, "controlvm", name, "usbattach", device)
}

// USBDetach removes a hot-plugged device from a running machine.
func USBDetach(ctx context.Context, vboxManage, name, device string) error {
	return runSimple(ctx, vboxManage, "controlvm", name, "usbdetach", device)
}

// USBFilterSpec is a persistent capture filter's matching fields (empty
// fields match anything — VBoxManage's own semantics).
type USBFilterSpec struct {
	Name         string `json:"name"`
	VendorID     string `json:"vendor_id,omitempty"`
	ProductID    string `json:"product_id,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
}

// USBFilterAdd appends a persistent capture filter at index (0-based
// position in the machine's filter list).
func USBFilterAdd(ctx context.Context, vboxManage, name string, index int, spec *USBFilterSpec) error {
	args := []string{
		"usbfilter", "add", strconv.Itoa(index),
		"--target", name, "--name", spec.Name,
	}
	if spec.VendorID != "" {
		args = append(args, "--vendorid", spec.VendorID)
	}
	if spec.ProductID != "" {
		args = append(args, "--productid", spec.ProductID)
	}
	if spec.Manufacturer != "" {
		args = append(args, "--manufacturer", spec.Manufacturer)
	}
	if spec.Product != "" {
		args = append(args, "--product", spec.Product)
	}
	if spec.SerialNumber != "" {
		args = append(args, "--serialnumber", spec.SerialNumber)
	}
	return runConfig(ctx, vboxManage, args...)
}

// USBFilterRemove deletes the filter at index (0-based).
func USBFilterRemove(ctx context.Context, vboxManage, name string, index int) error {
	return runConfig(ctx, vboxManage, "usbfilter", "remove", strconv.Itoa(index), "--target", name)
}
