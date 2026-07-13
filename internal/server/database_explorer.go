package server

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Read-only database explorer (GET /database/{db}/tables and
// /database/{db}/tables/{table}/rows) — zoneweaver's explorer drill-down on
// the same wire contract, so the UI calls one path family on every agent.
// {db} names a GET /database/stats databases[].name value. No arbitrary SQL:
// {table} and order_by are looked up in the database's OWN catalog first and
// quoted as identifiers; limit/offset ride as bind parameters.

// quoteIdent renders a catalog-verified name as a quoted SQL identifier.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// findDatabase resolves the {db} path value against the open databases.
func (s *Server) findDatabase(w http.ResponseWriter, r *http.Request) *DBHandle {
	name := r.PathValue("db")
	names := make([]string, 0, len(s.dbs))
	for i := range s.dbs {
		if s.dbs[i].Name == name {
			return &s.dbs[i]
		}
		names = append(names, s.dbs[i].Name)
	}
	errorResponse(w, http.StatusNotFound,
		"Unknown database — one of: "+strings.Join(names, ", "), "")
	return nil
}

// catalogTables lists the database's own tables (SQLite internals excluded).
func catalogTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master
		WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	names := []string{}
	for rows.Next() {
		var name string
		if serr := rows.Scan(&name); serr != nil {
			return nil, serr
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// catalogIndexes maps each table to its index names. Auto-indexes are excluded
// (they carry no schema of their own).
func catalogIndexes(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT tbl_name, name FROM sqlite_master
		WHERE type = 'index' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	indexes := map[string][]string{}
	for rows.Next() {
		var table, name string
		if serr := rows.Scan(&table, &name); serr != nil {
			return nil, serr
		}
		indexes[table] = append(indexes[table], name)
	}
	return indexes, rows.Err()
}

// tableColumns reads a table's column names in declaration order — SELECT *'s
// own order, and the vocabulary order_by is checked against.
func tableColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	var query strings.Builder
	query.WriteString("PRAGMA table_info(")
	query.WriteString(quoteIdent(table))
	query.WriteString(")")

	rows, err := db.QueryContext(ctx, query.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	columns := []string{}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if serr := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); serr != nil {
			return nil, serr
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

// tableRowCount counts a table's rows.
func tableRowCount(ctx context.Context, db *sql.DB, table string) (int64, error) {
	var query strings.Builder
	query.WriteString("SELECT COUNT(*) FROM ")
	query.WriteString(quoteIdent(table))

	var count int64
	err := db.QueryRowContext(ctx, query.String()).Scan(&count)
	return count, err
}

// handleListDatabaseTables serves GET /database/{db}/tables.
func (s *Server) handleListDatabaseTables(w http.ResponseWriter, r *http.Request) {
	handle := s.findDatabase(w, r)
	if handle == nil {
		return
	}
	names, err := catalogTables(r.Context(), handle.DB)
	if err != nil {
		slog.Error("list database tables", "database", handle.Name, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to list database tables", err.Error())
		return
	}
	indexes, err := catalogIndexes(r.Context(), handle.DB)
	if err != nil {
		slog.Error("list database indexes", "database", handle.Name, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to list database tables", err.Error())
		return
	}

	tables := make([]map[string]any, 0, len(names))
	for _, name := range names {
		count, cerr := tableRowCount(r.Context(), handle.DB, name)
		if cerr != nil {
			slog.Error("count table rows", "database", handle.Name, "table", name, "error", cerr)
			errorResponse(w, http.StatusInternalServerError, "Failed to list database tables", cerr.Error())
			return
		}
		list := indexes[name]
		if list == nil {
			list = []string{}
		}
		tables = append(tables, map[string]any{
			"name":    name,
			"rows":    count,
			"indexes": list,
		})
	}
	successResponse(w, "Database tables retrieved successfully", map[string]any{
		"database": handle.Name,
		"tables":   tables,
	})
}

// browseWindow clamps the page window: default 50, hard ceiling 500.
func browseWindow(r *http.Request) (limit, offset int) {
	limit, offset = 50, 0
	if parsed, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && parsed > 0 {
		limit = min(parsed, 500)
	}
	if parsed, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && parsed > 0 {
		offset = parsed
	}
	return limit, offset
}

// pageQuery builds the row page — SELECT * with an optional catalog-verified
// ORDER BY column; the window rides as bind parameters. No order_by leaves the
// table's natural rowid order.
func pageQuery(table, orderColumn string, descending bool) string {
	var query strings.Builder
	query.WriteString("SELECT * FROM ")
	query.WriteString(quoteIdent(table))
	if orderColumn != "" {
		query.WriteString(" ORDER BY ")
		query.WriteString(quoteIdent(orderColumn))
		if descending {
			query.WriteString(" DESC")
		} else {
			query.WriteString(" ASC")
		}
	}
	query.WriteString(" LIMIT ? OFFSET ?")
	return query.String()
}

// scanValues reads the result set as ordered value arrays (the explorer's
// rows[][] shape). TEXT and BLOB both arrive as bytes from the driver — they
// render as strings so the JSON carries the value itself, not base64.
func scanValues(rows *sql.Rows) ([][]any, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	values := [][]any{}
	for rows.Next() {
		row := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range row {
			targets[i] = &row[i]
		}
		if serr := rows.Scan(targets...); serr != nil {
			return nil, serr
		}
		for i, value := range row {
			if raw, ok := value.([]byte); ok {
				row[i] = string(raw)
			}
		}
		values = append(values, row)
	}
	return values, rows.Err()
}

// handleBrowseDatabaseTable serves GET
// /database/{db}/tables/{table}/rows?limit&offset&order_by — order_by is a
// column name, optionally suffixed :desc (e.g. created_at:desc).
func (s *Server) handleBrowseDatabaseTable(w http.ResponseWriter, r *http.Request) {
	handle := s.findDatabase(w, r)
	if handle == nil {
		return
	}
	table := r.PathValue("table")
	names, err := catalogTables(r.Context(), handle.DB)
	if err != nil {
		slog.Error("list database tables", "database", handle.Name, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to browse database table", err.Error())
		return
	}
	if !slices.Contains(names, table) {
		errorResponse(w, http.StatusNotFound, "Unknown table in "+handle.Name, "")
		return
	}
	columns, err := tableColumns(r.Context(), handle.DB, table)
	if err != nil {
		slog.Error("read table columns", "database", handle.Name, "table", table, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to browse database table", err.Error())
		return
	}

	orderColumn, direction, _ := strings.Cut(r.URL.Query().Get("order_by"), ":")
	if orderColumn != "" && !slices.Contains(columns, orderColumn) {
		errorResponse(w, http.StatusBadRequest, "order_by must name a column of "+table, "")
		return
	}
	limit, offset := browseWindow(r)

	total, err := tableRowCount(r.Context(), handle.DB, table)
	if err != nil {
		slog.Error("count table rows", "database", handle.Name, "table", table, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to browse database table", err.Error())
		return
	}
	rows, err := handle.DB.QueryContext(r.Context(),
		pageQuery(table, orderColumn, strings.EqualFold(direction, "desc")), limit, offset)
	if err != nil {
		slog.Error("browse table rows", "database", handle.Name, "table", table, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to browse database table", err.Error())
		return
	}
	defer func() {
		_ = rows.Close()
	}()

	values, err := scanValues(rows)
	if err != nil {
		slog.Error("scan table rows", "database", handle.Name, "table", table, "error", err)
		errorResponse(w, http.StatusInternalServerError, "Failed to browse database table", err.Error())
		return
	}

	successResponse(w, "Table rows retrieved successfully", map[string]any{
		"database": handle.Name,
		"table":    table,
		"columns":  columns,
		"rows":     values,
		"total":    total,
		"pagination": map[string]any{
			"limit":   limit,
			"offset":  offset,
			"hasMore": int64(offset+len(values)) < total,
		},
	})
}
