package machines

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// DocString coerces a document value to string (the handlers read the
// rendered document's box tuple through it).
func DocString(value any, fallback string) string {
	return stringOr(value, fallback)
}

// DocInt coerces a document value to int64 (the server's resource validation
// reads vcpus through it).
func DocInt(value any, fallback int64) int64 {
	return intOr(value, fallback)
}

// ConsolePortProblem validates a PRESENT settings.consoleport value against
// the VRDE TCP port range (converged, sync 2026-07-17 — both agents ship the
// identical refusal): the 0.1.31 package defaults consoleport to server_id,
// and an id above 65535 otherwise surfaces as a cryptic mid-chain modifyvm
// E_INVALIDARG. Numbers and numeric strings must be an integer in 1025-65535;
// anything else answers the refusal with the value verbatim. "" = valid.
// Absence is the caller's business — an absent consoleport is always fine.
func ConsolePortProblem(value any) string {
	refusal := func(text string) string {
		return "consoleport " + text + " is outside the valid console port range (1025-65535)"
	}
	inRange := func(n int64) bool { return n >= 1025 && n <= 65535 }
	switch v := value.(type) {
	case int:
		if !inRange(int64(v)) {
			return refusal(strconv.Itoa(v))
		}
	case int64:
		if !inRange(v) {
			return refusal(strconv.FormatInt(v, 10))
		}
	case uint64:
		if v > math.MaxInt64 || !inRange(int64(v)) {
			return refusal(strconv.FormatUint(v, 10))
		}
	case float64:
		if v != math.Trunc(v) || !inRange(int64(v)) {
			return refusal(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || !inRange(n) {
			return refusal(v)
		}
	default:
		return refusal(fmt.Sprint(value))
	}
	return ""
}

// VCPUProblem validates a PRESENT settings.vcpus value (converged, sync
// 2026-07-17 — zoneweaver's proposal, ACKED; both agents ship the identical
// refusal): a whole number >= 1. Integers pass; an INTEGRAL float like 2.0
// PASSES — it is whole, and the 0.1.31 template renders 2.0 from the
// wizard's integer 2 — while 2.5, zero, negatives, and non-numerics answer
// the refusal with the value verbatim. Numeric strings parse as floats
// (ParseInt alone would reject "2.0") and take the same whole-number test.
// "" = valid. Absence is the caller's business — an absent vcpus keeps the
// existing default-2 behavior byte-identical.
func VCPUProblem(value any) string {
	refusal := func(text string) string {
		return "vcpus " + text + " is not a valid vCPU count (whole number >= 1)"
	}
	wholeAtLeastOne := func(v float64) bool {
		return !math.IsNaN(v) && !math.IsInf(v, 0) && v == math.Trunc(v) && v >= 1
	}
	switch v := value.(type) {
	case int:
		if v < 1 {
			return refusal(strconv.Itoa(v))
		}
	case int64:
		if v < 1 {
			return refusal(strconv.FormatInt(v, 10))
		}
	case uint64:
		if v < 1 {
			return refusal(strconv.FormatUint(v, 10))
		}
	case float64:
		if !wholeAtLeastOne(v) {
			return refusal(strconv.FormatFloat(v, 'f', -1, 64))
		}
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || !wholeAtLeastOne(n) {
			return refusal(v)
		}
	default:
		return refusal(fmt.Sprint(value))
	}
	return ""
}

// VCPUCount coerces a guard-passed vcpus value to its canonical INTEGER
// (converged v2, sync 2026-07-17 — apply-time normalization): the SAME
// float-tolerant parsing as VCPUProblem, the whole float truncating to int —
// so a value the guard passed NEVER falls back to the default at apply time
// (intOr's ParseInt would drop the string "4.0" to the fallback and silently
// apply the wrong count). Non-parseable answers fallback — the guard already
// refused those upstream.
func VCPUCount(value any, fallback int64) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		if v > math.MaxInt64 {
			return fallback
		}
		return int64(v)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fallback
		}
		return int64(v)
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return fallback
		}
		return int64(n)
	}
	return fallback
}

// MemoryToMB exposes the memory size parser (Hosts.rb's rules) for the
// server's resource validation.
func MemoryToMB(value any) int64 { return memoryToMB(value) }

// SizeToMB exposes the disk size parser (Hosts.rb's rules) for the server's
// resource validation.
func SizeToMB(value any) int64 { return sizeToMB(value) }

// Generic document-value coercions (the document is YAML/JSON-typed).
func stringOr(value any, fallback string) string {
	switch v := value.(type) {
	case string:
		if v != "" {
			return v
		}
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return fallback
}

func intOr(value any, fallback int64) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		if v > math.MaxInt64 {
			return fallback
		}
		return int64(v)
	case float64:
		return int64(v)
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func mapOr(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func listOr(value any) []any {
	if l, ok := value.([]any); ok {
		return l
	}
	return nil
}

// sizePattern extracts the numeric part of a size string ("48G", "512M").
var sizePattern = regexp.MustCompile(`(\d+(?:\.\d+)?)`)

// sizeToMB converts a disk-size value to megabytes (Hosts.rb's rule: G → ×
// 1024; M → as-is; bare numbers are gigabytes for disks).
func sizeToMB(value any) int64 {
	s := strings.TrimSpace(stringOr(value, ""))
	if s == "" {
		return 0
	}
	match := sizePattern.FindString(s)
	if match == "" {
		return 0
	}
	number, err := strconv.ParseFloat(match, 64)
	if err != nil {
		return 0
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "m") {
		return int64(number)
	}
	return int64(number * 1024)
}

// memoryToMB converts the memory setting to megabytes (Hosts.rb: gb/g →
// × 1024, mb/m → as-is; bare numbers are megabytes).
func memoryToMB(value any) int64 {
	s := strings.TrimSpace(stringOr(value, ""))
	if s == "" {
		return 2048
	}
	match := sizePattern.FindString(s)
	if match == "" {
		return 2048
	}
	number, err := strconv.ParseFloat(match, 64)
	if err != nil {
		return 2048
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "g") {
		return int64(number * 1024)
	}
	return int64(number)
}
