package validation

import (
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

// Schema is one JSON Schema node as parsed from YAML or JSON.
type Schema = map[string]any

var (
	emailPattern    = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	ipv4Pattern     = regexp.MustCompile(`^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$`)
	datePattern     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	integerPattern  = regexp.MustCompile(`^-?\d+$`)
	numberPattern   = regexp.MustCompile(`^-?\d+(?:\.\d+)?$`)
)

const nonBlankPattern = `\S`

var formats = map[string]func(string) bool{
	"email":    emailPattern.MatchString,
	"uri":      isURI,
	"hostname": func(v string) bool { return len(v) <= 255 && hostnamePattern.MatchString(v) },
	"ipv4":     ipv4Pattern.MatchString,
	"date":     datePattern.MatchString,
}

func isURI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != ""
}

func isObject(value any) bool {
	_, ok := value.(map[string]any)
	return ok
}

func isArray(value any) bool {
	_, ok := value.([]any)
	return ok
}

func asNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func isInteger(value any) bool {
	switch v := value.(type) {
	case int, int64, uint64:
		return true
	case float64:
		return v == math.Trunc(v)
	case json.Number:
		return integerPattern.MatchString(v.String())
	case string:
		return integerPattern.MatchString(v)
	default:
		return false
	}
}

func typeOK(schemaType string, value any) bool {
	switch schemaType {
	case "string":
		_, ok := value.(string)
		return ok
	case "integer":
		return isInteger(value)
	case "number":
		if s, ok := value.(string); ok {
			return numberPattern.MatchString(s)
		}
		_, ok := asNumber(value)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "array":
		return isArray(value)
	case "object":
		return isObject(value)
	default:
		return true
	}
}

func str(schema Schema, key string) (string, bool) {
	v, ok := schema[key].(string)
	return v, ok
}

func num(schema Schema, key string) (float64, bool) {
	v, ok := schema[key]
	if !ok {
		return 0, false
	}
	return asNumber(v)
}

func failure(rule string, params map[string]any) *problem.Error {
	return &problem.Error{Rule: rule, Params: params}
}

func typeCheck(rule Schema, value any, _ string) *problem.Error {
	t, ok := str(rule, "type")
	if !ok || typeOK(t, value) {
		return nil
	}
	return failure("type", map[string]any{"type": t})
}

func nonBlankCheck(rule Schema, value any, _ string) *problem.Error {
	pattern, _ := str(rule, "pattern")
	s, isString := value.(string)
	if pattern != nonBlankPattern || !isString || strings.TrimSpace(s) != "" {
		return nil
	}
	return failure("pattern", map[string]any{"pattern": "nonBlank"})
}

func lengthCheck(rule Schema, value any, _ string) *problem.Error {
	s, ok := value.(string)
	if !ok {
		return nil
	}
	length := float64(len([]rune(s)))
	if minLength, has := num(rule, "minLength"); has && length < minLength {
		return failure("minLength", map[string]any{"minLength": minLength})
	}
	if maxLength, has := num(rule, "maxLength"); has && length > maxLength {
		return failure("maxLength", map[string]any{"maxLength": maxLength})
	}
	return nil
}

func patternCheck(rule Schema, value any, patternName string) *problem.Error {
	s, ok := value.(string)
	pattern, has := str(rule, "pattern")
	if !ok || !has {
		return nil
	}
	expression, err := regexp.Compile(pattern)
	if err != nil || expression.MatchString(s) {
		return nil
	}
	name := patternName
	if name == "" {
		if pattern == nonBlankPattern {
			name = "nonBlank"
		} else {
			name = pattern
		}
	}
	return failure("pattern", map[string]any{"pattern": name})
}

func boundsCheck(rule Schema, value any, _ string) *problem.Error {
	number, ok := asNumber(value)
	if !ok {
		return nil
	}
	if minimum, has := num(rule, "minimum"); has && number < minimum {
		return failure("minimum", map[string]any{"minimum": minimum})
	}
	if maximum, has := num(rule, "maximum"); has && number > maximum {
		return failure("maximum", map[string]any{"maximum": maximum})
	}
	return nil
}

func stringOf(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		raw, _ := json.Marshal(v)
		return string(raw)
	}
}

func enumCheck(rule Schema, value any, _ string) *problem.Error {
	options, ok := rule["enum"].([]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(options))
	for _, option := range options {
		if stringOf(option) == stringOf(value) {
			return nil
		}
		names = append(names, stringOf(option))
	}
	return failure("enum", map[string]any{"enum": strings.Join(names, ", ")})
}

func formatCheck(rule Schema, value any, _ string) *problem.Error {
	s, ok := value.(string)
	format, has := str(rule, "format")
	if !ok || !has {
		return nil
	}
	check, known := formats[format]
	if !known || check(s) {
		return nil
	}
	return failure("format", map[string]any{"format": format})
}

func itemsCheck(rule Schema, value any, _ string) *problem.Error {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	count := float64(len(list))
	if minItems, has := num(rule, "minItems"); has && count < minItems {
		return failure("minItems", map[string]any{"minItems": minItems})
	}
	if maxItems, has := num(rule, "maxItems"); has && count > maxItems {
		return failure("maxItems", map[string]any{"maxItems": maxItems})
	}
	return nil
}

type check func(rule Schema, value any, patternName string) *problem.Error

var blankChecks = []check{typeCheck, nonBlankCheck, lengthCheck, patternCheck}

var allChecks = append(append([]check{}, blankChecks...), boundsCheck, enumCheck, formatCheck, itemsCheck)
