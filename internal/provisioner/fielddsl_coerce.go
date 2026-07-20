package provisioner

import (
	"math"
	"strconv"
	"strings"
)

// Loose manifest-value coercions (YAML/JSON-typed input).
func anyString(value any) string {
	s, _ := value.(string)
	return s
}

func anyBool(value any) bool {
	b, _ := value.(bool)
	return b
}

func anyList(value any) []any {
	l, _ := value.([]any)
	return l
}

func anyInt(value any, fallback int64) int64 {
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

func anyFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float64:
		return v, true
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f, true
		}
	}
	return 0, false
}
