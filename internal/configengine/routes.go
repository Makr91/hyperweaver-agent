package configengine

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

// Auth carries the backend's guards and its actor resolver.
type Auth struct {
	Admin func(http.Handler) http.Handler
	Actor func(*http.Request) string
	User  string
}

// SavedResponse is the answer of a successful PUT /api/config/{name}.
type SavedResponse struct {
	Message         string         `json:"message" example:"Configuration saved."`
	RequiresRestart []RestartEntry `json:"requires_restart"`
}

// MessageResponse carries one sentence for curl and the log.
type MessageResponse struct {
	Message string `json:"message"`
}

// SetupStatusResponse is the answer of GET /api/setup/status.
type SetupStatusResponse struct {
	SetupComplete bool `json:"setup_complete"`
}

// VerifyTokenRequest is the body of POST /api/setup/verify-token.
type VerifyTokenRequest struct {
	Token string `json:"token"`
}

// SetupConfigsResponse is the answer of GET /api/setup.
type SetupConfigsResponse struct {
	Configs map[string]any `json:"configs"`
}

// SetupSchemasResponse is the answer of GET /api/setup/schema.
type SetupSchemasResponse struct {
	Schemas map[string]any `json:"schemas"`
}

// SetupPutRequest is the body of PUT /api/setup.
type SetupPutRequest struct {
	Configs map[string]any `json:"configs"`
}

// UploadResponse is the answer of POST /api/config/{name}/upload.
type UploadResponse struct {
	Path string `json:"path"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (e *Engine) knownName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.known(r.PathValue("name")) {
			problem.NotFound(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (e *Engine) setupOpen(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if e.setupComplete() {
			problem.NotFound(w)
			return
		}
		next(w, r)
	}
}

func bearerOf(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return ""
}

func (e *Engine) setupGuard(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(e.setupOpen(func(w http.ResponseWriter, r *http.Request) {
		if !e.tokenMatches(bearerOf(r)) {
			problem.Forbidden(w)
			return
		}
		next(w, r)
	}))
}

func (e *Engine) adminOrSetup(auth Auth, next http.HandlerFunc) http.Handler {
	admin := auth.Admin(http.HandlerFunc(next))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e.tokenMatches(bearerOf(r)) {
			next(w, r)
			return
		}
		admin.ServeHTTP(w, r)
	})
}

func decodeObject(r *http.Request) (map[string]any, bool) {
	var body map[string]any
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil || body == nil {
		return nil, false
	}
	return normalize(body).(map[string]any), true
}

func configValidation(w http.ResponseWriter, errs []problem.Error) {
	problem.Refuse(w, errs, "The configuration did not pass validation.")
}

// Routes mounts the configuration and setup routes of the contract on mux.
func (e *Engine) Routes(mux *http.ServeMux, auth Auth, exit func(), uploadLimit int64) {
	e.serviceUser = auth.User
	e.auth = auth
	e.exit = exit
	e.uploadLimit = uploadLimit
	admin := func(next http.HandlerFunc) http.Handler { return auth.Admin(http.HandlerFunc(next)) }

	mux.Handle("GET /api/config/restart-status", admin(e.handleRestartStatus))
	mux.Handle("POST /api/config/restart", admin(e.handleRestart))
	mux.Handle("GET /api/config/{name}/schema", e.knownName(admin(e.handleSchema)))
	mux.Handle("POST /api/config/{name}/upload", e.knownName(e.adminOrSetup(auth, e.handleUpload)))
	mux.Handle("GET /api/config/{name}", e.knownName(admin(e.handleGet)))
	mux.Handle("PUT /api/config/{name}", e.knownName(admin(e.handlePut)))
	mux.HandleFunc("GET /api/setup/status", e.handleSetupStatus)
	mux.HandleFunc("POST /api/setup/verify-token", e.setupOpen(e.handleVerifyToken))
	mux.Handle("GET /api/setup", e.setupGuard(e.handleSetupGet))
	mux.Handle("GET /api/setup/schema", e.setupGuard(e.handleSetupSchema))
	mux.Handle("PUT /api/setup", e.setupGuard(e.handleSetupPut))
}

// @Summary		The pending restart list
// @Description	Minimum role: admin. The union of every write's restart list since the last restart, with the last writer and time.
// @Tags			Configuration
// @Produce		json
// @Success		200	{object}	RestartStatus	"The pending list"
// @Router			/api/config/restart-status [get]
func (e *Engine) handleRestartStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, e.RestartPending())
}

// @Summary		Restart the agent
// @Description	Minimum role: admin. Clears the pending list, answers 202 and restarts the process after the answer: under systemd a clean exit and Restart=always, elsewhere the agent spawns its own successor.
// @Tags			Configuration
// @Produce		json
// @Success		202	{object}	MessageResponse	"Restarting"
// @Router			/api/config/restart [post]
func (e *Engine) handleRestart(w http.ResponseWriter, _ *http.Request) {
	e.ClearRestart()
	writeJSON(w, http.StatusAccepted, MessageResponse{Message: "Restarting."})
	go e.exit()
}

// @Summary		Read the schema of one configuration file
// @Description	Minimum role: admin. The JSON Schema 2020-12 document shipped inside the agent, verbatim: every rule and every title and description the editor draws.
// @Tags			Configuration
// @Produce		json
// @Param			name	path		string					true	"app, auth, db, machines or storage"
// @Success		200		{object}	map[string]interface{}	"The schema"
// @Failure		404		{object}	problem.Body			"Not a configuration file name"
// @Router			/api/config/{name}/schema [get]
func (e *Engine) handleSchema(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, e.Schema(r.PathValue("name")))
}

// @Summary		Read one configuration file
// @Description	Minimum role: admin. The raw file parsed to JSON and nothing else: no default filled, no value masked, no key added or removed.
// @Tags			Configuration
// @Produce		json
// @Param			name	path		string					true	"app, auth, db, machines or storage"
// @Success		200		{object}	map[string]interface{}	"The file"
// @Failure		404		{object}	problem.Body			"Not a configuration file name"
// @Router			/api/config/{name} [get]
func (e *Engine) handleGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, e.Raw(r.PathValue("name")))
}

// @Summary		Write one configuration file
// @Description	Minimum role: admin. The body is a JSON Merge Patch (RFC 7396) over the raw file: a sent key replaces the stored value, an omitted key is untouched, null removes a key, an array replaces whole. The filled merge is evaluated against the schema and the agent's own rules before anything is written; a 422 carries every failing value with its pointer into the body as sent. The 200 lists the changed values that need a restart.
// @Tags			Configuration
// @Accept			json
// @Produce		json
// @Param			name	path		string					true	"app, auth, db, machines or storage"
// @Param			body	body		map[string]interface{}	true	"The merge patch"
// @Success		200		{object}	SavedResponse			"Written"
// @Failure		400		{object}	problem.Body			"Unreadable body"
// @Failure		404		{object}	problem.Body			"Not a configuration file name"
// @Failure		422		{object}	problem.Body			"A value breaks a rule, or a readOnly key was sent"
// @Router			/api/config/{name} [put]
func (e *Engine) handlePut(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeObject(r)
	if !ok {
		problem.BadRequest(w)
		return
	}
	diff, err := e.Save(r.PathValue("name"), body, e.auth.Actor(r))
	var verr *ValidationError
	if errors.As(err, &verr) {
		configValidation(w, verr.Errors)
		return
	}
	if err != nil {
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	if diff == nil {
		diff = []RestartEntry{}
	}
	writeJSON(w, http.StatusOK, SavedResponse{Message: "Configuration saved.", RequiresRestart: diff})
}

// @Summary		Whether setup is complete
// @Description	No authentication. setup_complete is true exactly when the setup token file does not exist; on a desktop run it is always true.
// @Tags			Setup
// @Produce		json
// @Success		200	{object}	SetupStatusResponse	"The gate"
// @Router			/api/setup/status [get]
func (e *Engine) handleSetupStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, SetupStatusResponse{SetupComplete: e.setupComplete()})
}

// @Summary		Verify the setup token
// @Description	No authentication. 204 on a constant-time match with the token file, 403 otherwise, 404 once setup is complete. The browser keeps the token it sent as the bearer of every later setup call.
// @Tags			Setup
// @Accept			json
// @Param			body	body	VerifyTokenRequest	true	"The token"
// @Success		204		"Matched"
// @Failure		403		{object}	problem.Body	"Mismatched"
// @Failure		404		{object}	problem.Body	"Setup is complete"
// @Router			/api/setup/verify-token [post]
func (e *Engine) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	var body VerifyTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !e.tokenMatches(body.Token) {
		problem.Forbidden(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// @Summary		Read every configuration file for the setup page
// @Description	Under Authorization: Bearer with the setup token. The raw files under configs; 403 on a missing or mismatched token, 404 once setup is complete.
// @Tags			Setup
// @Produce		json
// @Success		200	{object}	SetupConfigsResponse	"The files"
// @Failure		403	{object}	problem.Body			"Missing or mismatched token"
// @Failure		404	{object}	problem.Body			"Setup is complete"
// @Router			/api/setup [get]
func (e *Engine) handleSetupGet(w http.ResponseWriter, _ *http.Request) {
	configs := map[string]any{}
	for _, name := range e.names {
		configs[name] = e.Raw(name)
	}
	writeJSON(w, http.StatusOK, SetupConfigsResponse{Configs: configs})
}

// @Summary		Read every schema for the setup page
// @Description	Under the setup token. Every schema under schemas; 403 and 404 as GET /api/setup.
// @Tags			Setup
// @Produce		json
// @Success		200	{object}	SetupSchemasResponse	"The schemas"
// @Failure		403	{object}	problem.Body			"Missing or mismatched token"
// @Failure		404	{object}	problem.Body			"Setup is complete"
// @Router			/api/setup/schema [get]
func (e *Engine) handleSetupSchema(w http.ResponseWriter, _ *http.Request) {
	schemas := map[string]any{}
	for _, name := range e.names {
		schemas[name] = e.Schema(name)
	}
	writeJSON(w, http.StatusOK, SetupSchemasResponse{Schemas: schemas})
}

// @Summary		Write every configuration file from the setup page
// @Description	Under the setup token. The body is {configs: {name: merge patch}}; every file is evaluated before any is written, the 422 carrying pointers as /configs/name/...; on success every file is written with the actor setup, the token is deleted and {message} is answered.
// @Tags			Setup
// @Accept			json
// @Produce		json
// @Param			body	body		SetupPutRequest	true	"One merge patch per file"
// @Success		200		{object}	MessageResponse	"Setup complete"
// @Failure		400		{object}	problem.Body	"Unreadable body"
// @Failure		403		{object}	problem.Body	"Missing or mismatched token"
// @Failure		404		{object}	problem.Body	"Setup is complete"
// @Failure		422		{object}	problem.Body	"A value of one of the files breaks its schema"
// @Router			/api/setup [put]
func (e *Engine) handleSetupPut(w http.ResponseWriter, r *http.Request) {
	body, ok := decodeObject(r)
	if !ok {
		problem.BadRequest(w)
		return
	}
	configs, isObject := body["configs"].(map[string]any)
	if !isObject {
		problem.BadRequest(w)
		return
	}
	patches := map[string]map[string]any{}
	for name, patch := range configs {
		object, _ := patch.(map[string]any)
		patches[name] = object
	}
	err := e.SaveAll(patches, "setup")
	var verr *ValidationError
	if errors.As(err, &verr) {
		configValidation(w, verr.Errors)
		return
	}
	if err != nil {
		problem.Write(w, http.StatusInternalServerError, "internal", "", nil)
		return
	}
	e.deleteSetupToken()
	writeJSON(w, http.StatusOK, MessageResponse{Message: "Setup complete."})
}

// @Summary		Upload the file a configuration property points at
// @Description	Admin session or setup token. Multipart with the parts file and pointer, the pointer naming a property whose action.kind is upload; the upload is written to the path that property holds, under the configuration directory, mode 0600.
// @Tags			Configuration
// @Accept			multipart/form-data
// @Produce		json
// @Param			name	path		string	true	"app, auth, db, machines or storage"
// @Param			file	formData	file	true	"The file"
// @Param			pointer	formData	string	true	"The property's JSON pointer"
// @Success		200		{object}	UploadResponse	"Written"
// @Failure		404		{object}	problem.Body	"Not a configuration file name"
// @Failure		413		{object}	problem.Body	"Larger than the upload limit"
// @Failure		422		{object}	problem.Body	"The pointer names no upload property, or the path is outside the configuration directory"
// @Router			/api/config/{name}/upload [post]
func (e *Engine) handleUpload(w http.ResponseWriter, r *http.Request) {
	uploadLimit := e.uploadLimit
	r.Body = http.MaxBytesReader(w, r.Body, uploadLimit+64*1024)
	if err := r.ParseMultipartForm(uploadLimit); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			problem.Write(w, http.StatusRequestEntityTooLarge, "payload-too-large", "", nil)
			return
		}
		problem.BadRequest(w)
		return
	}
	name := r.PathValue("name")
	pointer := r.FormValue("pointer")
	property := propertyAt(e.Schema(name), pointer)
	action, _ := property["action"].(map[string]any)
	if property == nil || action["kind"] != "upload" {
		configValidation(w, []problem.Error{{Pointer: "/pointer", Rule: "pointer", Params: map[string]any{}}})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		configValidation(w, []problem.Error{{Pointer: "/file", Rule: "required", Params: map[string]any{}}})
		return
	}
	defer func() { _ = file.Close() }()
	if header.Size > uploadLimit {
		problem.Write(w, http.StatusRequestEntityTooLarge, "payload-too-large", "", nil)
		return
	}
	content, rerr := io.ReadAll(io.LimitReader(file, uploadLimit))
	if rerr != nil {
		problem.BadRequest(w)
		return
	}
	if failure := e.writeUpload(name, pointer, content); failure != nil {
		configValidation(w, []problem.Error{*failure})
		return
	}
	value, _ := e.GetAt(name, pointer).(string)
	writeJSON(w, http.StatusOK, UploadResponse{Path: value})
}
