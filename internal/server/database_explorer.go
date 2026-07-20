package server

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
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

type databaseTable struct {
	Indexes []string `json:"indexes"`
	Name    string   `json:"name"`
	Rows    int64    `json:"rows"`
}

type databaseTablesResponse struct {
	Database  string          `json:"database"`
	Message   string          `json:"message"`
	Success   bool            `json:"success"`
	Tables    []databaseTable `json:"tables"`
	Timestamp string          `json:"timestamp"`
}

// handleListDatabaseTables serves GET /database/{db}/tables.
//
//	@Summary		List a database's tables
//	@Description	Minimum role: viewer. The read-only explorer drill-down (zoneweaver's contract, same wire on both agents): one open database's tables with row counts and index names. {db} is a GET /database/stats databases[].name value. SQLite internals (sqlite_*) and auto-indexes are excluded.
//	@Tags			Database Management
//	@Produce		json
//	@Param			db	path	string	true	"Database name from GET /database/stats databases[].name"
//	@Success		200	{object}	databaseTablesResponse	"Tables retrieved"
//	@Failure		404	{object}	wrappedError	"Unknown database (the message names the legal values)"
//	@Failure		500	{object}	wrappedError	"Failed to list database tables"
//	@Router			/database/{db}/tables [get]
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

	tables := make([]databaseTable, 0, len(names))
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
		tables = append(tables, databaseTable{
			Name:    name,
			Rows:    count,
			Indexes: list,
		})
	}
	writeJSON(w, databaseTablesResponse{
		Database:  handle.Name,
		Message:   "Database tables retrieved successfully",
		Success:   true,
		Tables:    tables,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
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

type databaseRowsPage struct {
	HasMore bool `json:"hasMore"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
}

type databaseRowsResponse struct {
	Columns    []string         `json:"columns"`
	Database   string           `json:"database"`
	Message    string           `json:"message"`
	Pagination databaseRowsPage `json:"pagination"`
	// One array per row, values in columns[] order (TEXT/BLOB render as strings, NULL as null)
	Rows      [][]any `json:"rows"`
	Success   bool    `json:"success"`
	Table     string  `json:"table"`
	Timestamp string  `json:"timestamp"`
	// Total rows in the table (not the page)
	Total int64 `json:"total"`
}

// handleBrowseDatabaseTable serves GET
// /database/{db}/tables/{table}/rows?limit&offset&order_by — order_by is a
// column name, optionally suffixed :desc (e.g. created_at:desc).
//
//	@Summary		Browse a table's rows (read-only, paged)
//	@Description	Minimum role: viewer. The explorer's row browser — NO arbitrary SQL. The table must exist in the named database and order_by must name one of ITS columns; both are looked up in the database's own catalog and quoted as identifiers, never interpolated raw, and limit/offset ride as bind parameters. order_by takes a column name optionally suffixed :desc (e.g. created_at:desc); without it rows come in the table's natural rowid order. rows[] are VALUE ARRAYS in columns[] order.
//	@Tags			Database Management
//	@Produce		json
//	@Param			db	path	string	true	"Database name from GET /database/stats databases[].name"
//	@Param			table	path	string	true	"Table name"
//	@Param			limit	query	integer	false	"Page size"	default(50)
//	@Param			offset	query	integer	false	"Page offset"	default(0)
//	@Param			order_by	query	string	false	"Column name, optionally with :desc"
//	@Success		200	{object}	databaseRowsResponse	"Rows retrieved"
//	@Failure		400	{object}	wrappedError	"order_by does not name a column of the table"
//	@Failure		404	{object}	wrappedError	"Unknown database or unknown table"
//	@Failure		500	{object}	wrappedError	"Failed to browse database table"
//	@Router			/database/{db}/tables/{table}/rows [get]
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

	writeJSON(w, databaseRowsResponse{
		Columns:  columns,
		Database: handle.Name,
		Message:  "Table rows retrieved successfully",
		Pagination: databaseRowsPage{
			HasMore: int64(offset+len(values)) < total,
			Limit:   limit,
			Offset:  offset,
		},
		Rows:      values,
		Success:   true,
		Table:     table,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Total:     total,
	})
}
