package machines

import (
	"context"
	"database/sql"
	"fmt"
)

// UsedServerID is one row of the GET /machines/ids listing.
type UsedServerID struct {
	ServerID    string `json:"server_id"`
	MachineName string `json:"machine_name"`
	Status      string `json:"status"`
}

// UsedServerIDs lists machines that carry a server_id, ascending.
func (s *Store) UsedServerIDs(ctx context.Context) ([]UsedServerID, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT server_id, name, status
		FROM machines WHERE server_id IS NOT NULL ORDER BY server_id ASC`)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	used := []UsedServerID{}
	for rows.Next() {
		var u UsedServerID
		if serr := rows.Scan(&u.ServerID, &u.MachineName, &u.Status); serr != nil {
			return nil, serr
		}
		used = append(used, u)
	}
	return used, rows.Err()
}

// NextServerID computes max(MAX+1, start) over stored server_ids,
// zero-padded to 4 digits (the Node agent's generateNextServerId with its
// zones.server_id_start floor). server_id defaults to auto-assigned per
// design D-G.
func (s *Store) NextServerID(ctx context.Context, start int) (string, error) {
	var highest sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(CAST(server_id AS INTEGER))
		FROM machines WHERE server_id IS NOT NULL`).Scan(&highest)
	if err != nil {
		return "", err
	}
	next := int64(start)
	if highest.Valid && highest.Int64 >= next {
		next = highest.Int64 + 1
	}
	return fmt.Sprintf("%04d", next), nil
}
