package assets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// The HCL download-portal flow (SHI's HCLDownloader, ported per Mark's
// ruling — the full implementation): exchange the stored refresh token for
// an access token (persisting the ROTATED refresh token back immediately —
// losing it breaks the next run), look the file up in the portal catalog
// (its sha256 is authoritative and overwrites the expectation), stream the
// download into the cache, verify, promote. No auto-retry; failures carry
// contextual guidance.

// OpHCLDownload is the HCL portal download task operation.
const OpHCLDownload = "hcl_download"

// The portal endpoints (SHI's constants).
const (
	hclExchangeURL    = "https://api.hcltechsw.com/v1/apitokens/exchange"
	hclCatalogURL     = "https://my.hcltechsw.com/files/domino"
	hclDownloadURLFmt = "https://api.hcltechsw.com/v1/files/%s/download"
)

// HCLTokens accesses the named HCL download-portal refresh token and
// persists its rotation (the secrets store implements this).
type HCLTokens interface {
	HCLToken(name string) (string, bool)
	UpdateHCLToken(name, token string) error
}

// HCLDownloadMetadata is the hcl_download task's metadata document. KeyName
// names an hcl_download_portal_api_keys secret; the token itself never
// enters task metadata.
type HCLDownloadMetadata struct {
	KeyName  string `json:"key_name"`
	Filename string `json:"filename"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
}

// Validate checks an HCL download request before it becomes a task.
func (m *HCLDownloadMetadata) Validate() error {
	if m.KeyName == "" {
		return errors.New("key_name (an hcl_download_portal_api_keys secret) is required")
	}
	if !ValidRole(m.Role) {
		return errors.New("role is not usable")
	}
	if !RoleKeyed(m.Kind) {
		return errors.New("kind must be installer, fixpack, or hotfix")
	}
	if !ValidFilename(m.Filename) {
		return errors.New("filename is not usable — it must match the HCL catalog name exactly")
	}
	return nil
}

// hclDownload executes one hcl_download task end to end.
func (e *executors) hclDownload(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	var meta HCLDownloadMetadata
	if len(task.Metadata) == 0 {
		return errors.New("hcl_download task has no metadata")
	}
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return fmt.Errorf("parse hcl_download metadata: %w", err)
	}
	if err := meta.Validate(); err != nil {
		return err
	}

	refresh, ok := e.hcl.HCLToken(meta.KeyName)
	if !ok {
		return errors.New("no hcl_download_portal_api_keys secret named " + meta.KeyName)
	}

	out.Write("stdout", "Exchanging HCL portal token "+meta.KeyName+"\n")
	access, rotated, err := hclExchange(ctx, refresh)
	if err != nil {
		return err
	}
	// The rotation persists BEFORE anything else can fail — SHI's critical
	// rule: reusing the stale token breaks the next run.
	if rotated != "" && rotated != refresh {
		if uerr := e.hcl.UpdateHCLToken(meta.KeyName, rotated); uerr != nil {
			out.Write("stderr", "CRITICAL: persisting the rotated HCL refresh token failed ("+
				uerr.Error()+") — future downloads with this key will fail until it is re-entered\n")
		} else {
			out.Write("stdout", "Rotated HCL refresh token persisted\n")
		}
	}

	out.Write("stdout", "Locating "+meta.Filename+" in the HCL catalog\n")
	fileID, catalogSHA, err := hclCatalogLookup(ctx, access, meta.Filename)
	if err != nil {
		return err
	}
	out.Write("stdout", "Catalog entry "+fileID+" (sha256 "+catalogSHA+")\n")

	// Downloads land in the kind's default location (built-in cache first).
	location, err := e.store.DefaultLocation(ctx, meta.Kind)
	if err != nil {
		return fmt.Errorf("no enabled %s storage location: %w", meta.Kind, err)
	}

	// The catalog's hash is authoritative — it overwrites the expectation
	// (SHI rule) and the download must reproduce it.
	if serr := e.store.SetExpectation(ctx, location.ID, meta.Role, meta.Kind, meta.Filename, catalogSHA); serr != nil {
		out.Write("stderr", "record catalog expectation failed: "+serr.Error()+"\n")
	}

	target, err := PathFor(location, meta.Role, meta.Filename)
	if err != nil {
		return err
	}
	if merr := os.MkdirAll(filepath.Dir(target), 0o750); merr != nil {
		return merr
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf(hclDownloadURLFmt, fileID), http.NoBody)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+access)

	out.Write("stdout", "Downloading "+meta.Filename+" from the HCL portal\n")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("HCL download failed: HTTP %s (an expired key or an un-accepted HCL license agreement are the usual causes)", response.Status)
	}

	temp := target + ".download"
	sha, size, err := e.streamToFile(task.ID, response.Body, temp, response.ContentLength)
	if err != nil {
		_ = os.Remove(temp)
		return err
	}
	if !strings.EqualFold(sha, catalogSHA) {
		_ = os.Remove(temp)
		return fmt.Errorf("hash mismatch: downloaded %s, catalog says %s — file discarded", sha, catalogSHA)
	}
	if rerr := os.Rename(temp, target); rerr != nil {
		_ = os.Remove(temp)
		return rerr
	}

	artifact, err := e.store.RecordIngested(ctx, &Ingested{
		LocationID: location.ID, Role: meta.Role, Kind: meta.Kind,
		Filename: meta.Filename, Path: target, SHA256: sha, Size: size,
		SourceURL: fmt.Sprintf(hclDownloadURLFmt, fileID),
	})
	if err != nil {
		return err
	}
	if rerr := e.store.RefreshLocationStats(ctx, location.ID); rerr != nil {
		out.Write("stderr", "location stats refresh failed: "+rerr.Error()+"\n")
	}
	out.Write("stdout", "Downloaded and verified "+artifact.Filename+" ("+sha+", "+
		strconv.FormatInt(size, 10)+" bytes)\n")
	return nil
}

// hclExchange trades the refresh token for an access token, returning the
// rotated refresh token alongside. Field names are matched leniently — the
// portal has shipped both camelCase and snake_case.
func hclExchange(ctx context.Context, refresh string) (access, rotated string, err error) {
	payload, err := json.Marshal(map[string]string{"refreshToken": refresh})
	if err != nil {
		return "", "", err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(reqCtx, http.MethodPost, hclExchangeURL,
		bytes.NewReader(payload))
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HCL token exchange failed: HTTP %s (is the download-portal key still valid?)", response.Status)
	}

	var document map[string]any
	if derr := json.NewDecoder(response.Body).Decode(&document); derr != nil {
		return "", "", fmt.Errorf("parse token exchange response: %w", derr)
	}
	access = firstString(document, "accessToken", "access_token", "token")
	rotated = firstString(document, "refreshToken", "refresh_token")
	if access == "" {
		return "", "", errors.New("HCL token exchange returned no access token (expired or revoked portal key?)")
	}
	return access, rotated, nil
}

// hclCatalogLookup finds the catalog entry matching filename exactly and
// returns its file id and authoritative sha256. The catalog's nesting is
// walked generically so layout drift does not break the match.
func hclCatalogLookup(ctx context.Context, access, filename string) (id, sha string, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(reqCtx, http.MethodGet, hclCatalogURL, http.NoBody)
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Authorization", "Bearer "+access)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HCL catalog fetch failed: HTTP %s", response.Status)
	}

	var document any
	if derr := json.NewDecoder(response.Body).Decode(&document); derr != nil {
		return "", "", fmt.Errorf("parse HCL catalog: %w", derr)
	}
	id, sha = findCatalogEntry(document, filename)
	if id == "" {
		return "", "", errors.New(filename + " is not in the HCL catalog — the match is by EXACT name; check the portal's file listing")
	}
	if sha == "" {
		return "", "", errors.New(filename + " is in the HCL catalog but carries no sha256 — refusing an unverifiable download")
	}
	return id, sha, nil
}

// findCatalogEntry walks arbitrary catalog JSON for an object whose name
// field equals filename, returning its id and sha256.
func findCatalogEntry(node any, filename string) (id, sha string) {
	switch value := node.(type) {
	case map[string]any:
		name := firstString(value, "name", "fileName", "filename")
		if name == filename {
			foundID := firstString(value, "id", "fileId", "file_id", "_id")
			if foundID == "" {
				if number, ok := value["id"].(float64); ok {
					foundID = strconv.FormatFloat(number, 'f', -1, 64)
				}
			}
			foundSHA := firstString(value, "sha256", "checksum")
			if checksums, ok := value["checksums"].(map[string]any); ok && foundSHA == "" {
				foundSHA = firstString(checksums, "sha256")
			}
			if foundID != "" {
				return foundID, foundSHA
			}
		}
		for _, child := range value {
			if foundID, foundSHA := findCatalogEntry(child, filename); foundID != "" {
				return foundID, foundSHA
			}
		}
	case []any:
		for _, child := range value {
			if foundID, foundSHA := findCatalogEntry(child, filename); foundID != "" {
				return foundID, foundSHA
			}
		}
	}
	return "", ""
}

// firstString returns the first non-empty string among the document's keys.
func firstString(document map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := document[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
