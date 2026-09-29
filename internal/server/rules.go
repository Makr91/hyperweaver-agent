package server

import "net/http"

var estateDefs = map[string]any{
	"slug": map[string]any{
		"type":      "string",
		"allOf":     []any{map[string]any{"pattern": "^[A-Za-z0-9.-]+$"}, map[string]any{"not": map[string]any{"pattern": `\.\.`}}},
		"minLength": 1,
		"maxLength": 255,
	},
	"identifier": map[string]any{
		"type":      "string",
		"allOf":     []any{map[string]any{"pattern": "^[0-9a-zA-Z][0-9a-zA-Z._-]*$"}, map[string]any{"not": map[string]any{"pattern": `\.\.`}}},
		"maxLength": 255,
	},
	"email": map[string]any{
		"type":      "string",
		"pattern":   "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
		"maxLength": 255,
	},
	"orgCode":      map[string]any{"type": "string", "pattern": "^[0-9A-F]{6}$"},
	"providerName": map[string]any{"type": "string", "pattern": "^[a-z0-9_]+$"},
	"hex":          map[string]any{"type": "string", "pattern": "^[a-fA-F0-9]+$"},
	"watchId":      map[string]any{"type": "string", "pattern": "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"},
	"personName": map[string]any{
		"type":      "string",
		"pattern":   `^[^\x00-\x40\x5B-\x60\x7B-\x7F][^\x00-\x1F\x21-\x26\x28-\x2C\x2F-\x40\x5B-\x60\x7B-\x7F]*$`,
		"maxLength": 255,
	},
	"iconName": map[string]any{"type": "string", "pattern": "^[a-z0-9 -]{1,64}$"},
	"languageTag": map[string]any{
		"type":      "string",
		"pattern":   "^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$",
		"maxLength": 10,
	},
	"timezone": map[string]any{"type": "string", "pattern": "^(?:UTC|[A-Za-z_]+(?:/[A-Za-z0-9_+-]+)+)$"},
	"region":   map[string]any{"type": "string", "pattern": "^[A-Z]{2}$|^(EU|EEA|UK)$"},
}

type rulesDocument struct {
	Schema string         `json:"$schema" example:"https://json-schema.org/draft/2020-12/schema"`
	Defs   map[string]any `json:"$defs"`
	Forms  map[string]any `json:"forms"`
}

// @Summary		The validation rules
// @Description	Public, before login. One JSON Schema 2020-12 document: $defs carries the estate's named patterns every backend shares; forms lists the request bodies this agent's routes evaluate as object schemas, empty until the shared UI's hyperweaver pages declare their form keys, so every form validates required alone from the page's own declaration and the route still evaluates every write.
// @Tags			Status
// @Produce		json
// @Success		200	{object}	rulesDocument	"The rules"
// @Router			/api/rules [get]
func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, rulesDocument{
		Schema: "https://json-schema.org/draft/2020-12/schema",
		Defs:   estateDefs,
		Forms:  map[string]any{},
	})
}
