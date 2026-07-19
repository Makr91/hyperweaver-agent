package vbox

import (
	"context"
	"fmt"
	"os/exec"
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

// VMCounters are one machine's cumulative byte counters from the VM
// debugger's statistics (`debugvm statistics`) — network receive/transmit and
// disk read/write since the VM process started. HasNet/HasDisk report whether
// the family answered at all.
type VMCounters struct {
	NetRxBytes       int64
	NetTxBytes       int64
	DiskReadBytes    int64
	DiskWrittenBytes int64
	HasNet           bool
	HasDisk          bool
}

// DebugVMCounters sums the machine's network/disk byte counters across its
// devices.
func DebugVMCounters(ctx context.Context, vboxManage, target string) (*VMCounters, error) {
	cmd := exec.CommandContext(ctx, vboxManage, "debugvm", target, "statistics",
		"--pattern", "*ReceiveBytes|*TransmitBytes|*ReadBytes|*WrittenBytes")
	cmd.SysProcAttr = procattr.NoConsole()
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("VBoxManage debugvm %s statistics: %w", target, err)
	}
	counters := &VMCounters{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "/") {
			continue
		}
		n, perr := strconv.ParseInt(fields[1], 10, 64)
		if perr != nil {
			continue
		}
		switch {
		case strings.HasSuffix(fields[0], "ReceiveBytes"):
			counters.NetRxBytes += n
			counters.HasNet = true
		case strings.HasSuffix(fields[0], "TransmitBytes"):
			counters.NetTxBytes += n
			counters.HasNet = true
		case strings.HasSuffix(fields[0], "ReadBytes"):
			counters.DiskReadBytes += n
			counters.HasDisk = true
		case strings.HasSuffix(fields[0], "WrittenBytes"):
			counters.DiskWrittenBytes += n
			counters.HasDisk = true
		}
	}
	return counters, nil
}
