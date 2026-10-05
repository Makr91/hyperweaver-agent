package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

const (
	searchPath         = "/api/search"
	searchQueryMin     = 2
	searchQueryMax     = 200
	searchLimitDefault = 5
	searchLimitMax     = 50
	searchListLimit    = 10000
	openSearchPath     = "/opensearch.xml"
)

var searchKindOrder = []string{"machine", "config", "template", "artifact"}

type searchCount struct {
	Value    int    `json:"value"`
	Relation string `json:"relation" example:"eq"`
}

type searchHighlight struct {
	Text  string   `json:"text"`
	Spans [][2]int `json:"spans"`
}

type searchResult struct {
	Kind         string                     `json:"kind"`
	ID           string                     `json:"id"`
	Collection   *string                    `json:"collection"`
	Org          string                     `json:"org"`
	Name         string                     `json:"name"`
	Version      string                     `json:"version"`
	Provider     string                     `json:"provider"`
	Architecture string                     `json:"architecture"`
	Anchor       string                     `json:"anchor"`
	Source       map[string]string          `json:"source"`
	Score        int                        `json:"score"`
	Title        string                     `json:"title"`
	Subtitle     string                     `json:"subtitle"`
	Matched      string                     `json:"matched"`
	Highlight    map[string]searchHighlight `json:"highlight"`
	Facets       map[string]string          `json:"facets"`
}

type searchResponse struct {
	Query   string                 `json:"query"`
	Kinds   []string               `json:"kinds"`
	Scope   string                 `json:"scope"`
	Counts  map[string]searchCount `json:"counts"`
	Results []searchResult         `json:"results"`
	Next    *string                `json:"next"`
}

type searchField struct {
	field string
	text  string
}

type searchEntry struct {
	fields []searchField
	row    searchResult
}

type searchMatch struct {
	score     int
	matched   string
	highlight map[string]searchHighlight
}

func (s *Server) searchKinds() []string {
	kinds := []string{"machine", "config", "template"}
	if s.cfg.ArtifactStorage.Enabled {
		kinds = append(kinds, "artifact")
	}
	return kinds
}

func searchRow(kind, id, title, subtitle string) searchResult {
	return searchResult{
		Kind:      kind,
		ID:        id,
		Name:      id,
		Title:     title,
		Subtitle:  subtitle,
		Highlight: map[string]searchHighlight{},
		Facets:    map[string]string{},
	}
}

func joinParts(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, " · ")
}

func (s *Server) machineEntries(ctx context.Context) []searchEntry {
	list, err := s.machines.List(ctx, &machines.ListFilter{})
	if err != nil {
		slog.Warn("search: list machines", "error", err)
		return nil
	}
	entries := make([]searchEntry, 0, len(list))
	for _, machine := range list {
		notes := ""
		if machine.Notes != nil {
			notes = *machine.Notes
		}
		var tags []string
		if machine.Tags != nil {
			_ = json.Unmarshal(machine.Tags, &tags)
		}
		row := searchRow("machine", machine.Name, machine.Name, joinParts(machine.Hypervisor, machine.Status))
		row.Facets["status"] = machine.Status
		entries = append(entries, searchEntry{
			fields: []searchField{
				{field: "name", text: machine.Name},
				{field: "notes", text: notes},
				{field: "tags", text: strings.Join(tags, " ")},
			},
			row: row,
		})
	}
	return entries
}

func (s *Server) configEntries(admin bool) []searchEntry {
	if !admin {
		return nil
	}
	entries := make([]searchEntry, 0, len(config.Names))
	for _, name := range config.Names {
		title, _ := s.cfg.Engine().Schema(name)["title"].(string)
		entries = append(entries, searchEntry{
			fields: []searchField{
				{field: "name", text: name},
				{field: "title", text: title},
			},
			row: searchRow("config", name, name, title),
		})
	}
	return entries
}

func (s *Server) templateEntries(ctx context.Context) []searchEntry {
	list, err := s.machines.ListTemplates(ctx)
	if err != nil {
		slog.Warn("search: list templates", "error", err)
		return nil
	}
	entries := make([]searchEntry, 0, len(list))
	for _, template := range list {
		name := template.Organization + "/" + template.BoxName
		id := strconv.FormatInt(template.ID, 10)
		row := searchRow("template", id, name, joinParts(template.Version, template.Provider, template.Architecture))
		row.Name = name
		row.Anchor = id
		row.Version = template.Version
		row.Provider = template.Provider
		row.Architecture = template.Architecture
		entries = append(entries, searchEntry{
			fields: []searchField{
				{field: "name", text: name},
				{field: "version", text: template.Version},
				{field: "architecture", text: template.Architecture},
				{field: "provider", text: template.Provider},
				{field: "source", text: template.SourceName},
			},
			row: row,
		})
	}
	return entries
}

func (s *Server) artifactEntries(ctx context.Context) []searchEntry {
	if !s.cfg.ArtifactStorage.Enabled {
		return nil
	}
	list, err := s.assets.List(ctx, &assets.ListFilter{Limit: searchListLimit})
	if err != nil {
		slog.Warn("search: list artifacts", "error", err)
		return nil
	}
	entries := make([]searchEntry, 0, len(list))
	for _, artifact := range list {
		id := strconv.FormatInt(artifact.ID, 10)
		row := searchRow("artifact", id, artifact.Filename, joinParts(artifact.Kind, artifact.Role, artifact.Version))
		row.Name = artifact.Filename
		row.Anchor = id
		row.Facets["file_type"] = artifact.Kind
		entries = append(entries, searchEntry{
			fields: []searchField{
				{field: "name", text: artifact.Filename},
				{field: "role", text: artifact.Role},
				{field: "type", text: artifact.Kind},
				{field: "version", text: artifact.Version},
			},
			row: row,
		})
	}
	return entries
}

func (s *Server) searchEntries(ctx context.Context, kinds map[string]bool, admin bool) []searchEntry {
	entries := []searchEntry{}
	if kinds["machine"] {
		entries = append(entries, s.machineEntries(ctx)...)
	}
	if kinds["config"] {
		entries = append(entries, s.configEntries(admin)...)
	}
	if kinds["template"] {
		entries = append(entries, s.templateEntries(ctx)...)
	}
	if kinds["artifact"] {
		entries = append(entries, s.artifactEntries(ctx)...)
	}
	return entries
}

func nameScore(name string, words []string) int {
	phrase := strings.Join(words, " ")
	if name == phrase {
		return 3
	}
	if strings.HasPrefix(name, phrase) {
		return 2
	}
	for _, word := range words {
		if !strings.Contains(name, word) {
			return 0
		}
	}
	return 1
}

func spansOf(lower string, words []string) [][2]int {
	spans := [][2]int{}
	for _, word := range words {
		at := strings.Index(lower, word)
		if at < 0 {
			continue
		}
		start := utf8.RuneCountInString(lower[:at])
		spans = append(spans, [2]int{start, start + utf8.RuneCountInString(word)})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	return spans
}

func matchSearchFields(fields []searchField, words []string) (searchMatch, bool) {
	if len(words) == 0 || len(fields) == 0 {
		return searchMatch{}, false
	}
	lowered := make([]string, len(fields))
	for i, entry := range fields {
		lowered[i] = strings.ToLower(entry.text)
	}
	for _, word := range words {
		found := false
		for _, lower := range lowered {
			if strings.Contains(lower, word) {
				found = true
				break
			}
		}
		if !found {
			return searchMatch{}, false
		}
	}
	for i, lower := range lowered {
		for _, word := range words {
			if strings.Contains(lower, word) {
				return searchMatch{
					score:   nameScore(lowered[0], words),
					matched: fields[i].field,
					highlight: map[string]searchHighlight{
						fields[i].field: {Text: fields[i].text, Spans: spansOf(lower, words)},
					},
				}, true
			}
		}
	}
	return searchMatch{}, false
}

func positionIn(title string, words []string) int {
	lower := strings.ToLower(title)
	best := -1
	for _, word := range words {
		at := strings.Index(lower, word)
		if at >= 0 && (best < 0 || at < best) {
			best = at
		}
	}
	if best < 0 {
		return int(^uint(0) >> 1)
	}
	return best
}

func sortSearchResults(results []searchResult, words []string) {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if pa, pb := positionIn(a.Title, words), positionIn(b.Title, words); pa != pb {
			return pa < pb
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return a.ID < b.ID
	})
}

func searchInScope(scope string) bool {
	return !strings.HasPrefix(scope, "org:") && !strings.HasPrefix(scope, "collection:")
}

func searchCursor(offset int) *string {
	cursor := base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
	return &cursor
}

func searchOffset(after string) int {
	raw, err := base64.RawURLEncoding.DecodeString(after)
	if err != nil {
		return 0
	}
	offset, err := strconv.Atoi(string(raw))
	if err != nil || offset < 0 {
		return 0
	}
	return offset
}

func searchLimit(raw string) int {
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		return searchLimitDefault
	}
	if limit > searchLimitMax {
		return searchLimitMax
	}
	return limit
}

func (s *Server) parseSearchKinds(raw string) (named, kinds []string) {
	answered := s.searchKinds()
	for _, kind := range strings.Split(raw, ",") {
		kind = strings.TrimSpace(kind)
		for _, known := range answered {
			if kind == known {
				named = append(named, kind)
			}
		}
	}
	if len(named) == 0 {
		return []string{}, answered
	}
	return named, named
}

// @Summary		Search this agent
// @Description	Minimum role: viewer. The navbar contract's search over this agent's own rows: machine (name, notes, tags), config (file name and schema title, admin keys alone, as the configuration routes are admin-only), template (organization/box, version, architecture, provider, source) and artifact (filename, role, type, version; only while artifact_storage.enabled, when the kind is listed). Every word of q matches case-insensitively as a substring; a hit carries kind, id (a natural key per kind: the machine name, the file name, the template id, the artifact id), the locator members as deep as the hit goes (anchor the template or artifact id for the page's hash; version, provider and architecture on a template), score (3 the name equal to q, 2 a prefix, 1 every word inside the name, 0 another field), title, subtitle, matched, highlight as rune offsets into the matched field, and facets (status on a machine, file_type on an artifact). Results sort by score, then the match's position in the title, then title, then id; counts carry one exact value per kind. scope org:<name> or collection:<key> matches nothing here, an agent's rows belonging to no organization and no collection; any other scope is ignored. Each kind answers at most limit rows (1 to 50, default 5); while kinds names exactly one kind, after pages it and next is the cursor of the following page, else next is null. The answer carries Cache-Control: no-store.
// @Tags			Status
// @Produce		json
// @Param			q		query		string			true	"The text searched for, 2 to 200 characters"
// @Param			kinds	query		string			false	"Comma-separated kinds: machine, config, template, artifact; absent asks every kind"
// @Param			scope	query		string			false	"org:<name> or collection:<key>"
// @Param			limit	query		int				false	"Rows per kind, 1 to 50, default 5"
// @Param			after	query		string			false	"The cursor a previous answer's next carried, honoured while kinds names one kind"
// @Success		200		{object}	searchResponse	"The hits"
// @Failure		401		{object}	problem.Body	"Missing credential"
// @Failure		422		{object}	problem.Body	"q shorter than 2 or longer than 200 characters, the pointer /q"
// @Router			/api/search [get]
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	q := strings.TrimSpace(query.Get("q"))
	length := utf8.RuneCountInString(q)
	if length < searchQueryMin {
		problem.Invalid(w, problem.Rule("/q", "minLength", map[string]any{"minLength": searchQueryMin}))
		return
	}
	if length > searchQueryMax {
		problem.Invalid(w, problem.Rule("/q", "maxLength", map[string]any{"maxLength": searchQueryMax}))
		return
	}
	named, kinds := s.parseSearchKinds(query.Get("kinds"))
	scope := query.Get("scope")
	limit := searchLimit(query.Get("limit"))
	offset := 0
	if len(named) == 1 {
		offset = searchOffset(query.Get("after"))
	}
	wanted := map[string]bool{}
	for _, kind := range kinds {
		wanted[kind] = true
	}
	identity := auth.FromContext(r.Context())
	words := strings.Fields(strings.ToLower(q))

	found := []searchResult{}
	if searchInScope(scope) {
		entries := s.searchEntries(r.Context(), wanted, identity.Role == "admin")
		for i := range entries {
			match, ok := matchSearchFields(entries[i].fields, words)
			if !ok {
				continue
			}
			row := entries[i].row
			row.Score = match.score
			row.Matched = match.matched
			row.Highlight = match.highlight
			found = append(found, row)
		}
	}
	sortSearchResults(found, words)

	counts := map[string]searchCount{}
	results := []searchResult{}
	var next *string
	for _, kind := range searchKindOrder {
		if !wanted[kind] {
			continue
		}
		rows := []searchResult{}
		for i := range found {
			if found[i].Kind == kind {
				rows = append(rows, found[i])
			}
		}
		if len(rows) == 0 {
			continue
		}
		counts[kind] = searchCount{Value: len(rows), Relation: "eq"}
		start := offset
		if start > len(rows) {
			start = len(rows)
		}
		end := start + limit
		if end > len(rows) {
			end = len(rows)
		}
		results = append(results, rows[start:end]...)
		if len(named) == 1 && end < len(rows) {
			next = searchCursor(end)
		}
	}
	sortSearchResults(results, words)

	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, searchResponse{
		Query:   q,
		Kinds:   named,
		Scope:   scope,
		Counts:  counts,
		Results: results,
		Next:    next,
	})
}

var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

func firstForwarded(value string) string {
	return strings.TrimSpace(strings.Split(value, ",")[0])
}

func requestOrigin(r *http.Request) string {
	host := firstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	scheme := firstForwarded(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	return scheme + "://" + host
}

// @Summary		OpenSearch description
// @Description	No authentication. The OpenSearch 1.1 description of this agent at its own origin, the one the shared UI links as rel=search while search is listed, so a browser can add the agent as a search engine: ShortName and Description from brand.name, Image from brand.logo_url, and a text/html Url whose template is <origin>/search?q={searchTerms}, the origin the request was made to, the forwarded host and scheme first.
// @Tags			Status
// @Produce		application/opensearchdescription+xml
// @Success		200	{string}	string	"The description"
// @Router			/opensearch.xml [get]
func (s *Server) handleOpenSearch(w http.ResponseWriter, r *http.Request) {
	origin := requestOrigin(r)
	name := xmlEscaper.Replace(agentBrand.Name)
	lines := []string{
		`<?xml version="1.0" encoding="UTF-8"?>`,
		`<OpenSearchDescription xmlns="http://a9.com/-/spec/opensearch/1.1/">`,
		"  <ShortName>" + name + "</ShortName>",
		"  <Description>" + name + "</Description>",
		"  <InputEncoding>UTF-8</InputEncoding>",
		`  <Image type="image/svg+xml">` + xmlEscaper.Replace(origin+agentBrand.LogoURL) + "</Image>",
		`  <Url type="text/html" method="get" template="` + xmlEscaper.Replace(origin) + `/search?q={searchTerms}"/>`,
		"</OpenSearchDescription>",
		"",
	}
	w.Header().Set("Content-Type", "application/opensearchdescription+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if _, err := w.Write([]byte(strings.Join(lines, "\n"))); err != nil {
		slog.Error("write opensearch description", "error", err)
	}
}
