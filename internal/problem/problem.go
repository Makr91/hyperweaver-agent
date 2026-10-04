// Package problem writes RFC 9457 problem documents: the registry types, the rule errors with their pointers, and the sentences a rule renders.
package problem

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

const typeBase = "https://auth.startcloud.com/probs/"

var titles = map[string]string{
	"validation":         "The request did not pass validation.",
	"conflict":           "A value in the request is already taken.",
	"bad-request":        "The request could not be read.",
	"authentication":     "Authentication is required.",
	"forbidden":          "The request is not allowed.",
	"not-found":          "The resource was not found.",
	"payload-too-large":  "The request is too large.",
	"throttled":          "Too many requests.",
	"internal":           "The server could not complete the request.",
	"bad-gateway":        "The service behind this request could not be reached.",
	"not-configured":     "The service is not configured.",
	"method-not-allowed": "The method is not allowed.",
}

var details = map[string]string{
	"required":      "{{field}} is required.",
	"type":          "{{field}} must be of type {{type}}.",
	"minLength":     "{{field}} must be at least {{minLength}} characters.",
	"maxLength":     "{{field}} must be at most {{maxLength}} characters.",
	"pattern":       "{{field}} must match {{pattern}}.",
	"minimum":       "{{field}} must be at least {{minimum}}.",
	"maximum":       "{{field}} must be at most {{maximum}}.",
	"enum":          "{{field}} must be one of: {{enum}}.",
	"format":        "{{field}} must be a valid {{format}}.",
	"minItems":      "{{field}} must have at least {{minItems}} items.",
	"maxItems":      "{{field}} must have at most {{maxItems}} items.",
	"unique":        "{{field}} is already taken in {{scope}}.",
	"writable":      "{{field}} is not writable by the service user.",
	"reachable":     "{{field}} did not answer.",
	"readOnly":      "{{field}} is read-only.",
	"restartReason": "{{field}} requires a restart without a reason.",
	"pointer":       "{{field}} names no property that takes an upload.",
	"yaml":          "{{field}} could not be parsed as YAML: {{message}}.",
	"not":           "{{field}} is not allowed.",
}

// Error is one failing rule at a JSON pointer.
type Error struct {
	Pointer string         `json:"pointer"`
	Rule    string         `json:"rule"`
	Params  map[string]any `json:"params"`
	Detail  string         `json:"detail,omitempty"`
}

// Body is an RFC 9457 problem document.
type Body struct {
	Type   string  `json:"type"`
	Title  string  `json:"title"`
	Status int     `json:"status"`
	Detail string  `json:"detail,omitempty"`
	Errors []Error `json:"errors"`
}

var typeByStatus = map[int]string{
	http.StatusBadRequest:            "bad-request",
	http.StatusUnauthorized:          "authentication",
	http.StatusForbidden:             "forbidden",
	http.StatusNotFound:              "not-found",
	http.StatusMethodNotAllowed:      "method-not-allowed",
	http.StatusConflict:              "conflict",
	http.StatusRequestEntityTooLarge: "payload-too-large",
	http.StatusUnprocessableEntity:   "validation",
	http.StatusTooManyRequests:       "throttled",
	http.StatusInternalServerError:   "internal",
	http.StatusBadGateway:            "bad-gateway",
	http.StatusServiceUnavailable:    "not-configured",
}

// TypeFor answers the registry type bound to a status; internal for any other.
func TypeFor(status int) string {
	if t, ok := typeByStatus[status]; ok {
		return t
	}
	return "internal"
}

func fieldOf(pointer string) string {
	parts := strings.Split(pointer, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return ""
}

func render(template string, values map[string]any) string {
	out := template
	for key, value := range values {
		out = strings.ReplaceAll(out, "{{"+key+"}}", stringify(value))
	}
	return out
}

func stringify(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, ", ")
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

// DetailFor renders the English sentence of one error.
func DetailFor(e Error) string {
	template, ok := details[e.Rule]
	if !ok {
		return fieldOf(e.Pointer) + " failed " + e.Rule + "."
	}
	values := map[string]any{"field": fieldOf(e.Pointer)}
	for key, value := range e.Params {
		values[key] = value
	}
	return render(template, values)
}

// Write sends one problem body with the given status and type.
func Write(w http.ResponseWriter, status int, problemType, title string, errors []Error) {
	Send(w, status, problemType, title, "", errors, nil)
}

// Detail sends the status's registry type with one sentence for logs and other clients.
func Detail(w http.ResponseWriter, status int, detail string) {
	Send(w, status, TypeFor(status), "", detail, nil, nil)
}

// Send builds the body: the status's type, the title, the detail, the errors and any extra members a client may ignore.
func Send(w http.ResponseWriter, status int, problemType, title, detail string, errors []Error, members map[string]any) {
	if title == "" {
		title = titles[problemType]
	}
	body := map[string]any{
		"type":   typeBase + problemType,
		"title":  title,
		"status": status,
	}
	if detail != "" {
		body["detail"] = detail
	}
	list := make([]Error, 0, len(errors))
	for _, e := range errors {
		if e.Params == nil {
			e.Params = map[string]any{}
		}
		if e.Detail == "" {
			e.Detail = DetailFor(e)
		}
		list = append(list, e)
	}
	body["errors"] = list
	for key, value := range members {
		body[key] = value
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("write problem body", "error", err)
	}
}

// Conflict answers 409 with a detail sentence and extra members.
func Conflict(w http.ResponseWriter, detail string, members map[string]any) {
	Send(w, http.StatusConflict, "conflict", "", detail, nil, members)
}

// Required builds the required error at a pointer.
func Required(pointer string) Error {
	return Error{Pointer: pointer, Rule: "required", Params: map[string]any{}}
}

// Enum builds the enum error at a pointer.
func Enum(pointer string, allowed ...string) Error {
	return Error{Pointer: pointer, Rule: "enum", Params: map[string]any{"enum": strings.Join(allowed, ", ")}}
}

// Pattern builds the pattern error at a pointer, name the $defs name.
func Pattern(pointer, name string) Error {
	return Error{Pointer: pointer, Rule: "pattern", Params: map[string]any{"pattern": name}}
}

// Unique builds the unique error at a pointer within scope.
func Unique(pointer, scope string) Error {
	return Error{Pointer: pointer, Rule: "unique", Params: map[string]any{"scope": scope}}
}

// Rule builds any named rule at a pointer.
func Rule(pointer, rule string, params map[string]any) Error {
	if params == nil {
		params = map[string]any{}
	}
	return Error{Pointer: pointer, Rule: rule, Params: params}
}

// Invalid answers a failed write with the given errors: 409 when every rule is unique, 422 otherwise.
func Invalid(w http.ResponseWriter, errors ...Error) {
	Refuse(w, errors, "")
}

// Refuse answers a failed write: 409 conflict when every rule is unique, 422 validation otherwise.
func Refuse(w http.ResponseWriter, errors []Error, title string) {
	conflict := len(errors) > 0
	for _, e := range errors {
		if e.Rule != "unique" {
			conflict = false
			break
		}
	}
	if conflict {
		Write(w, http.StatusConflict, "conflict", title, errors)
		return
	}
	Write(w, http.StatusUnprocessableEntity, "validation", title, errors)
}

// NotFound answers 404 not-found.
func NotFound(w http.ResponseWriter) {
	Write(w, http.StatusNotFound, "not-found", "", nil)
}

// Forbidden answers 403 forbidden.
func Forbidden(w http.ResponseWriter) {
	Write(w, http.StatusForbidden, "forbidden", "", nil)
}

// BadRequest answers 400 bad-request.
func BadRequest(w http.ResponseWriter) {
	Write(w, http.StatusBadRequest, "bad-request", "", nil)
}
