// Package updater checks a remote versioninfo document for newer releases —
// the same mechanism SHI (static versioninfo.json URL) and the Node agent
// (updates.versioninfo_url) use. The release workflow publishes
// update-info.json as a release asset at a stable latest-download URL.
package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Info is the remote versioninfo document shape (Node-agent compatible).
type Info struct {
	Version     string `json:"version"`
	ReleaseURL  string `json:"releaseUrl"`
	ReleaseDate string `json:"releaseDate"`
	Changelog   string `json:"changelog"`
}

// Check fetches the versioninfo document and reports whether it advertises a
// version newer than currentVersion.
func Check(ctx context.Context, url, currentVersion string) (*Info, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, false, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("versioninfo fetch returned %s", resp.Status)
	}

	var info Info
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, false, err
	}
	if info.Version == "" {
		return nil, false, fmt.Errorf("versioninfo document has no version field")
	}

	return &info, CompareVersions(info.Version, currentVersion) > 0, nil
}

// CompareVersions compares two dotted version strings (leading v ignored):
// 1 when a > b, -1 when a < b, 0 when equal. Mirrors the Node agent.
func CompareVersions(a, b string) int {
	pa := strings.Split(strings.TrimPrefix(a, "v"), ".")
	pb := strings.Split(strings.TrimPrefix(b, "v"), ".")

	length := len(pa)
	if len(pb) > length {
		length = len(pb)
	}
	for i := 0; i < length; i++ {
		na, nb := 0, 0
		if i < len(pa) {
			na, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			nb, _ = strconv.Atoi(pb[i])
		}
		if na > nb {
			return 1
		}
		if na < nb {
			return -1
		}
	}
	return 0
}
