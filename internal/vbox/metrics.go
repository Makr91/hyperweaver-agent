package vbox

import (
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/procattr"
)

// VirtualBox's own per-VM telemetry, the two native facilities the Manager
// GUI's Resource Use tab reads: the metrics subsystem (IPerformanceCollector —
// CPU guest/VMM load, guest-additions RAM) and the VM debugger's statistics
// counters (cumulative network/disk bytes, diffed into rates by the caller).

// MetricsSetup enables metrics collection for one machine (`metrics setup
// --period 1 --samples 1`) — without it, queries answer no values.
func MetricsSetup(ctx context.Context, vboxManage, target string) error {
	return runSimple(ctx, vboxManage, "metrics", "setup", "--period", "1", "--samples", "1", target)
}

// MetricsQuery returns one machine's current metric values (`metrics query
// <target>`), keyed by metric name (CPU/Load/User, RAM/Usage/Used,
// Guest/RAM/Usage/Total, ...); values keep VirtualBox's own unit spelling
// ("0.42%", "620576 kB").
func MetricsQuery(ctx context.Context, vboxManage, target string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "metrics", "query", target)
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage metrics query %s: %w", target, err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 || !strings.Contains(fields[1], "/") {
			continue
		}
		values[fields[1]] = strings.Join(fields[2:], " ")
	}
	return values, nil
}

// MetricPercent parses a "%"-suffixed metric value.
func MetricPercent(value string) (float64, bool) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(value), "%")
	n, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// MetricKilobytes parses a "kB"-unit metric value into bytes.
func MetricKilobytes(value string) (int64, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
		return n * 1024, true
	}
	return n, true
}

// NetDeviceCounters are one network DEVICE INSTANCE's cumulative byte
// counters — the per-adapter split the topology edge widths ride. Adapter is
// instance+1: exact on uniform-driver machines (this agent's own creates);
// mixed-driver machines number instances PER TYPE (e1000-0 beside
// virtio-net-0), so Device stays alongside for disambiguation.
type NetDeviceCounters struct {
	Device  string
	Adapter int
	RxBytes int64
	TxBytes int64
}

// VMCounters are one machine's cumulative byte counters from the VM
// debugger's statistics (`debugvm statistics`) — network receive/transmit and
// disk read/write since the VM process started, summed across devices, plus
// the per-network-device split. HasNet/HasDisk report whether the family
// answered at all.
type VMCounters struct {
	NetRxBytes       int64
	NetTxBytes       int64
	DiskReadBytes    int64
	DiskWrittenBytes int64
	HasNet           bool
	HasDisk          bool
	PerNet           []NetDeviceCounters
}

// netDeviceKey extracts the device segment between /Devices/ and the counter
// leaf ("/Devices/e1000-0/ReceiveBytes" → "e1000-0"; instance-as-own-segment
// shapes fold their slashes into the key) — tolerant of either statistics
// path shape.
func netDeviceKey(path, leaf string) (string, bool) {
	rest, found := strings.CutPrefix(path, "/Devices/")
	if !found {
		return "", false
	}
	key, found := strings.CutSuffix(rest, "/"+leaf)
	if !found {
		return "", false
	}
	return key, key != ""
}

// deviceInstance reads the trailing integer of a device key ("e1000-0" → 0);
// -1 when none exists.
func deviceInstance(key string) int {
	end := len(key)
	start := end
	for start > 0 && key[start-1] >= '0' && key[start-1] <= '9' {
		start--
	}
	if start == end {
		return -1
	}
	n, err := strconv.Atoi(key[start:end])
	if err != nil {
		return -1
	}
	return n
}

// DebugVMCounters sums the machine's network/disk byte counters across its
// devices and keeps the per-network-device split.
func DebugVMCounters(ctx context.Context, vboxManage, target string) (*VMCounters, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "debugvm", target, "statistics",
		"--pattern", "*ReceiveBytes|*TransmitBytes|*ReadBytes|*WrittenBytes")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage debugvm %s statistics: %w", target, err)
	}
	var doc struct {
		Counters []struct {
			Value int64  `xml:"c,attr"`
			Name  string `xml:"name,attr"`
		} `xml:"Counter"`
	}
	if uerr := xml.Unmarshal(out, &doc); uerr != nil {
		return nil, fmt.Errorf("parse debugvm statistics: %w", uerr)
	}
	counters := &VMCounters{}
	perNet := map[string]*NetDeviceCounters{}
	addNet := func(path, leaf string, n int64, rx bool) {
		key, ok := netDeviceKey(path, leaf)
		if !ok {
			return
		}
		device := perNet[key]
		if device == nil {
			device = &NetDeviceCounters{Device: key, Adapter: deviceInstance(key) + 1}
			perNet[key] = device
		}
		if rx {
			device.RxBytes += n
		} else {
			device.TxBytes += n
		}
	}
	for _, counter := range doc.Counters {
		n := counter.Value
		switch {
		case strings.HasSuffix(counter.Name, "ReceiveBytes"):
			counters.NetRxBytes += n
			counters.HasNet = true
			addNet(counter.Name, "ReceiveBytes", n, true)
		case strings.HasSuffix(counter.Name, "TransmitBytes"):
			counters.NetTxBytes += n
			counters.HasNet = true
			addNet(counter.Name, "TransmitBytes", n, false)
		case strings.HasSuffix(counter.Name, "ReadBytes"):
			counters.DiskReadBytes += n
			counters.HasDisk = true
		case strings.HasSuffix(counter.Name, "WrittenBytes"):
			counters.DiskWrittenBytes += n
			counters.HasDisk = true
		}
	}
	for _, device := range perNet {
		counters.PerNet = append(counters.PerNet, *device)
	}
	sort.Slice(counters.PerNet, func(i, j int) bool {
		if counters.PerNet[i].Adapter != counters.PerNet[j].Adapter {
			return counters.PerNet[i].Adapter < counters.PerNet[j].Adapter
		}
		return counters.PerNet[i].Device < counters.PerNet[j].Device
	})
	return counters, nil
}
