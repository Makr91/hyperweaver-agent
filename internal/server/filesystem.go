package server

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// The host file browser — zoneweaver's browse surface (BrowseController.js +
// lib/filesystem FileSystemCore/FileSystemBrowse) ported: GET /filesystem
// lists agent-host directories under the file_browser.security bounds. This
// agent ships the BROWSE slice (the UI's path pickers and file manager);
// the mutate/archive family stays zoneweaver's until scheduled. Divergence
// from the base's item shape, honestly: uid/gid/atime/ctime are absent —
// Windows has no cross-platform analog; mtime and permissions survive.
//
// The base never had to define "/" — its root IS the illumos root. Here:
// file_browser.root set means "/" maps there and anything outside answers
// 403; unset means "/" lists the host's drive letters on Windows and the
// real root elsewhere.

// errBrowseForbidden classifies security rejections (the base's message-text
// mapping, as a typed error → 403).
var errBrowseForbidden = errors.New("forbidden")

// fileSystemItem is one listing entry (the base's getItemInfo shape, minus
// the platform-absent fields).
type fileSystemItem struct {
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	IsDirectory bool            `json:"isDirectory"`
	Size        *int64          `json:"size"`
	MimeType    *string         `json:"mimeType"`
	IsBinary    bool            `json:"isBinary"`
	Syntax      *string         `json:"syntax"`
	Permissions filePermissions `json:"permissions"`
	Mtime       time.Time       `json:"mtime"`
}

// filePermissions is the base's Unix-permission summary (on Windows the mode
// bits are Go's synthesized view: 0666/0444 by read-only attribute).
type filePermissions struct {
	Octal      string `json:"octal"`
	Readable   bool   `json:"readable"`
	Writable   bool   `json:"writable"`
	Executable bool   `json:"executable"`
}

// syntaxByExtension is the base's syntax-highlighting map.
var syntaxByExtension = map[string]string{
	".js": "javascript", ".json": "json", ".py": "python", ".sh": "bash",
	".yaml": "yaml", ".yml": "yaml", ".xml": "xml", ".html": "html",
	".css": "css", ".sql": "sql", ".conf": "apache", ".cfg": "ini",
	".ini": "ini", ".log": "log",
}

// fileBrowserGate answers 503 while file_browser.enabled is false (the
// base's disabled answer; the file-browser token disappears with it).
func (s *Server) fileBrowserGate(handler http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.FileBrowser.Enabled {
			taskError(w, http.StatusServiceUnavailable, "File browser is disabled")
			return
		}
		handler(w, r)
	})
}

// browseRoot answers file_browser.root in native absolute form, "" when the
// surface is unconfined.
func (s *Server) browseRoot() string {
	root := s.cfg.FileBrowser.Root
	if root == "" {
		return ""
	}
	abs, err := filepath.Abs(filepath.FromSlash(root))
	if err != nil {
		return ""
	}
	return abs
}

// sameBrowsePath compares two native paths as the platform does (Windows
// folds case).
func sameBrowsePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// pathWithin reports whether path sits at or below root (both native
// absolute).
func pathWithin(root, path string) bool {
	if sameBrowsePath(path, root) {
		return true
	}
	prefix := root
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if runtime.GOOS == "windows" {
		return strings.HasPrefix(strings.ToLower(path), strings.ToLower(prefix))
	}
	return strings.HasPrefix(path, prefix)
}

// validateBrowsePath ports the base's validatePath: traversal guard, browse
// root containment, forbidden prefixes, forbidden patterns. Prefix checks
// compare case-insensitively on Windows (its paths do).
func (s *Server) validateBrowsePath(raw string) (string, error) {
	security := s.cfg.FileBrowser.Security
	if security.PreventTraversal &&
		(strings.Contains(raw, "..") || strings.Contains(raw, "~")) {
		return "", fmt.Errorf("%w: directory traversal not allowed", errBrowseForbidden)
	}
	// Wire paths are forward-slash and the file manager roots them at "/"
	// (the base contract — its "/" IS the illumos root), so a Windows drive
	// path arrives as "/C:/Users/…". Left as-is, filepath.Abs reads
	// "\C:\Users\…" as CURRENT-DRIVE-relative and invents "G:\C:\Users\…"
	// (runtime-proven 2026-07-17: mkdir "G:\C:\Users\Mark\New Folder") —
	// strip the leading separators when a drive letter follows.
	native := filepath.FromSlash(raw)
	if runtime.GOOS == "windows" {
		trimmed := strings.TrimLeft(native, `\`)
		if len(trimmed) >= 2 && trimmed[1] == ':' {
			native = trimmed
		}
	}
	normalized, err := filepath.Abs(native)
	if err != nil {
		return "", fmt.Errorf("path validation error: %w", err)
	}
	if root := s.browseRoot(); root != "" && !pathWithin(root, normalized) {
		return "", fmt.Errorf("%w: path is outside the configured browse root", errBrowseForbidden)
	}
	compare := normalized
	if runtime.GOOS == "windows" {
		compare = strings.ToLower(filepath.ToSlash(compare))
	}
	for _, forbidden := range security.ForbiddenPaths {
		prefix := forbidden
		if runtime.GOOS == "windows" {
			prefix = strings.ToLower(filepath.ToSlash(prefix))
		}
		if strings.HasPrefix(compare, prefix) {
			return "", fmt.Errorf("%w: access to %s is forbidden", errBrowseForbidden, forbidden)
		}
	}
	for _, pattern := range security.ForbiddenPatterns {
		expr, rerr := regexp.Compile(strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"))
		if rerr != nil {
			continue
		}
		if expr.MatchString(compare) {
			return "", fmt.Errorf("%w: path matches forbidden pattern %s", errBrowseForbidden, pattern)
		}
	}
	return normalized, nil
}

// isBinarySample ports the base's isBinaryFile: an 8KB head sample judged by
// null-byte (>1%) and control-character (>5%) density; unreadable files are
// assumed binary.
func isBinarySample(path string) bool {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return true
	}
	defer func() {
		_ = file.Close()
	}()
	buffer := make([]byte, 8192)
	read, err := io.ReadFull(file, buffer)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return true
	}
	if read == 0 {
		return false
	}
	sample := buffer[:read]
	nulls := 0
	controls := 0
	for _, b := range sample {
		if b == 0 {
			nulls++
		}
		if (b >= 1 && b <= 8) || b == 11 || b == 12 || (b >= 14 && b <= 31) || b == 127 {
			controls++
		}
	}
	if float64(nulls)/float64(read) > 0.01 {
		return true
	}
	return float64(controls)/float64(read) > 0.05
}

// browseItemInfo builds one entry from a stat result (getItemInfo's listing
// slice — the per-file work). Wire paths are FORWARD-SLASH on every platform
// (the base contract; Go accepts them back on Windows, so requests
// round-trip unchanged).
func browseItemInfo(path string, info os.FileInfo) fileSystemItem {
	item := fileSystemItem{
		Name:        info.Name(),
		Path:        filepath.ToSlash(path),
		IsDirectory: info.IsDir(),
		Mtime:       info.ModTime(),
	}
	mode := info.Mode()
	item.Permissions = filePermissions{
		Octal:      fmt.Sprintf("%o", mode.Perm()),
		Readable:   mode.Perm()&0o444 != 0,
		Writable:   mode.Perm()&0o222 != 0,
		Executable: mode.Perm()&0o111 != 0,
	}
	if info.IsDir() {
		return item
	}
	size := info.Size()
	item.Size = &size
	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	item.MimeType = &mimeType
	item.IsBinary = mode.IsRegular() && isBinarySample(path)
	if !item.IsBinary {
		syntax := syntaxByExtension[strings.ToLower(filepath.Ext(path))]
		if syntax == "" {
			syntax = "text"
		}
		item.Syntax = &syntax
	}
	return item
}

// listBrowseDirectory ports listDirectory: validate, stat, entry cap, per-
// entry info (failures skipped with the base's tolerance).
func (s *Server) listBrowseDirectory(dirPath string) ([]fileSystemItem, string, error) {
	normalized, err := s.validateBrowsePath(dirPath)
	if err != nil {
		return nil, "", err
	}
	normalized = filepath.Clean(normalized)
	stat, err := os.Stat(filepath.Clean(normalized))
	if err != nil {
		return nil, "", err
	}
	if !stat.IsDir() {
		return nil, "", errors.New("path is not a directory")
	}
	entries, err := os.ReadDir(filepath.Clean(normalized))
	if err != nil {
		return nil, "", err
	}
	limit := s.cfg.FileBrowser.Security.MaxDirectoryEntries
	if len(entries) > limit {
		return nil, "", fmt.Errorf("directory has %d entries, exceeding limit of %d", len(entries), limit)
	}
	items := make([]fileSystemItem, 0, len(entries))
	for _, entry := range entries {
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		items = append(items, browseItemInfo(filepath.Join(normalized, entry.Name()), info))
	}
	return items, normalized, nil
}

// driveItems enumerates mounted drive roots — the "/" answer on Windows when
// no browse root confines the surface. Forbidden drives are simply absent.
func (s *Server) driveItems() []fileSystemItem {
	items := []fileSystemItem{}
	for letter := 'A'; letter <= 'Z'; letter++ {
		native := string(letter) + `:\`
		info, err := os.Stat(native)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, verr := s.validateBrowsePath(native); verr != nil {
			continue
		}
		// Stat names a drive root "\" — the item carries the letter instead.
		item := browseItemInfo(native, info)
		item.Name = string(letter) + ":"
		item.Path = string(letter) + ":/"
		items = append(items, item)
	}
	return items
}

// browseParent answers parent_path: null at the top of the browse universe
// (the configured root, or a filesystem top); with no root on Windows the
// drives listing sits above drive roots.
func browseParent(normalized, root string) *string {
	if root != "" && sameBrowsePath(normalized, root) {
		return nil
	}
	parent := filepath.Dir(normalized)
	if parent == normalized {
		if root == "" && runtime.GOOS == "windows" {
			top := "/"
			return &top
		}
		return nil
	}
	slash := filepath.ToSlash(parent)
	return &slash
}

// browseResponse is GET /filesystem's directory listing (the base's
// browseDirectory answer).
type browseResponse struct {
	Items []fileSystemItem `json:"items"`
	// Forward-slash absolute path on every platform ("/" itself on the drive listing)
	CurrentPath string `json:"current_path"`
	// null at the browse top (the configured root, the drive listing, a filesystem root); a Windows drive root answers "/" when unconfined — navigation back to the drive listing. Forward-slash
	ParentPath          *string `json:"parent_path"`
	TotalItems          int     `json:"total_items"`
	HiddenItemsFiltered int     `json:"hidden_items_filtered"`
}

// browseListingError is the internal listing-failure body ({error, details} —
// the base's failure shape; the over-the-entry-cap refusal rides it too).
type browseListingError struct {
	Error   string `json:"error"`
	Details string `json:"details"`
}

// handleBrowseFilesystem serves GET /filesystem — the base's browseDirectory:
// list, hidden filter, user sort, parent path.
//
//	@Summary		Browse directory contents
//	@Description	Minimum role: operator (the file-browser capability token; the whole /filesystem surface is operator-gated by the central policy). Lists one agent-host directory — zoneweaver's browseDirectory: hidden-file filter, sortable, parent-path navigation. THE "/" REQUEST (the browse top): with file_browser.root configured, "/" maps to that directory and any path outside it answers 403 (the containment check rides every request); unconfined (root empty, the default), "/" answers the DRIVE-LETTER LISTING on Windows (one directory item per mounted drive — C:/, D:/, ... — current_path "/", parent_path null; drive roots' parent_path points back to "/") and the real filesystem root elsewhere. Security bounds from file_browser.security: traversal guard (".."/"~" rejected), forbidden path prefixes and glob patterns answer 403, directories over max_directory_entries answer 500 with details. 503 when file_browser.enabled is false (the token disappears with it).
//	@Tags			File System
//	@Produce		json
//	@Param			path		query	string	false	"Directory path to browse. \"/\" is the browse top: the configured file_browser.root when set, the Windows drive listing or the real root when not"	default(/)
//	@Param			show_hidden	query	bool	false	"Include dot-prefixed entries"	default(false)
//	@Param			sort_by		query	string	false	"Sort field"	Enums(name,size,modified,type)	default(name)
//	@Param			sort_order	query	string	false	"Sort direction"	Enums(asc,desc)	default(asc)
//	@Success		200	{object}	browseResponse	"Directory contents"
//	@Failure		403	"Path forbidden (traversal, outside the configured browse root, forbidden prefix, or pattern match)"
//	@Failure		404	"Directory not found"
//	@Failure		500	"Listing failure ({error, details} — includes the over-the-entry-cap refusal)"
//	@Failure		503	"File browser is disabled"
//	@Router			/filesystem [get]
func (s *Server) handleBrowseFilesystem(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	dirPath := query.Get("path")
	if dirPath == "" {
		dirPath = "/"
	}
	showHidden := query.Get("show_hidden") == "true"
	sortBy := query.Get("sort_by")
	sortOrder := query.Get("sort_order")

	root := s.browseRoot()
	if dirPath == "/" && root != "" {
		dirPath = root
	}

	var items []fileSystemItem
	currentPath := "/"
	var parentPath *string
	if dirPath == "/" && runtime.GOOS == "windows" {
		items = s.driveItems()
	} else {
		listed, normalized, err := s.listBrowseDirectory(dirPath)
		if err != nil {
			switch {
			case errors.Is(err, errBrowseForbidden):
				taskError(w, http.StatusForbidden, err.Error())
			case errors.Is(err, os.ErrNotExist):
				taskError(w, http.StatusNotFound, "Directory not found")
			default:
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				writeJSON(w, browseListingError{
					Error:   "Failed to browse directory",
					Details: err.Error(),
				})
			}
			return
		}
		items = listed
		currentPath = filepath.ToSlash(normalized)
		parentPath = browseParent(normalized, root)
	}

	total := len(items)
	if !showHidden {
		visible := items[:0]
		for _, item := range items {
			if !strings.HasPrefix(item.Name, ".") {
				visible = append(visible, item)
			}
		}
		items = visible
	}

	sort.SliceStable(items, func(i, j int) bool {
		a, b := &items[i], &items[j]
		var less bool
		switch sortBy {
		case "size":
			var av, bv int64
			if a.Size != nil {
				av = *a.Size
			}
			if b.Size != nil {
				bv = *b.Size
			}
			less = av < bv
		case "modified":
			less = a.Mtime.Before(b.Mtime)
		case "type":
			less = browseTypeKey(a) < browseTypeKey(b)
		default:
			less = strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		if sortOrder == "desc" {
			return !less
		}
		return less
	})

	// Wire paths are forward-slash on every platform (the base contract —
	// the file manager matches parent/child on '/').
	writeJSON(w, browseResponse{
		Items:               items,
		CurrentPath:         currentPath,
		ParentPath:          parentPath,
		TotalItems:          len(items),
		HiddenItemsFiltered: total - len(items),
	})
}

// browseTypeKey is the base's type-sort key: directories sort as
// "directory", files by their MIME type.
func browseTypeKey(item *fileSystemItem) string {
	if item.IsDirectory {
		return "directory"
	}
	if item.MimeType != nil {
		return *item.MimeType
	}
	return "file"
}
