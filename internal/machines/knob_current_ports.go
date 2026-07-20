package machines

import (
	"strconv"
	"strings"
)

// guestAgentWired reports whether uart2 carries the QGA channel: enabled, in
// server mode, onto a hyperweaver-qga pipe (Windows hosts) or qga.sock
// (elsewhere) — PUT's guest_agent toggle read backwards.
func guestAgentWired(raw map[string]string) bool {
	if _, _, ok := splitPortValue(raw["uart2"]); !ok {
		return false
	}
	kind, path, found := strings.Cut(raw["uartmode2"], ",")
	if !found || kind != "server" {
		return false
	}
	return strings.Contains(path, "hyperweaver-qga-") || strings.HasSuffix(path, "qga.sock")
}

// serialCurrent reads uartN="io_base,irq" + uartmodeN + uarttypeN into
// hardware.serial[] entries. Disabled ports (uartN="off") are unset — omitted.
func serialCurrent(raw map[string]string) []any {
	entries := []any{}
	for port := 1; port <= 4; port++ {
		n := strconv.Itoa(port)
		ioBase, irq, ok := splitPortValue(raw["uart"+n])
		if !ok {
			continue
		}
		entry := map[string]any{"port": port, "io_base": ioBase, "irq": irq}
		if mode := serialModeCurrent(raw["uartmode"+n]); mode != "" {
			entry["mode"] = mode
		}
		if uartType := raw["uarttype"+n]; uartType != "" {
			entry["type"] = uartType
		}
		entries = append(entries, entry)
	}
	return entries
}

// serialModeCurrent turns the emitter's "kind,path" forms into PUT's
// space-separated --uart-mode words; disconnected and bare host-device paths
// ride verbatim.
func serialModeCurrent(mode string) string {
	kind, path, found := strings.Cut(mode, ",")
	if !found {
		return mode
	}
	switch kind {
	case "file", "tcpserver", "tcpclient", "server", "client":
		return kind + " " + path
	}
	return mode
}

// parallelCurrent reads lptN="io_base,irq" + lptmodeN into
// hardware.parallel[] entries.
func parallelCurrent(raw map[string]string) []any {
	entries := []any{}
	for port := 1; port <= 2; port++ {
		n := strconv.Itoa(port)
		ioBase, irq, ok := splitPortValue(raw["lpt"+n])
		if !ok {
			continue
		}
		entry := map[string]any{"port": port, "io_base": ioBase, "irq": irq}
		if device := raw["lptmode"+n]; device != "" {
			entry["device"] = device
		}
		entries = append(entries, entry)
	}
	return entries
}

// splitPortValue parses the emitter's enabled-port "0x03f8,4" form; "off",
// absence, and malformed values answer !ok.
func splitPortValue(value string) (ioBase string, irq int64, ok bool) {
	if value == "" || value == "off" {
		return "", 0, false
	}
	ioBase, irqText, found := strings.Cut(value, ",")
	if !found {
		return "", 0, false
	}
	irq, err := strconv.ParseInt(irqText, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return ioBase, irq, true
}
