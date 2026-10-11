package updater

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	releasesPerPage  = 20
	releasesTimeout  = 30 * time.Second
	checksumsName    = "SHA256SUMS.txt"
	releaseBodyLimit = 8 << 20
)

// ReleaseAsset is one file of a repository release: its name, size in bytes, the sha256 the release's SHA256SUMS.txt lists or null, and its download URL.
type ReleaseAsset struct {
	Name               string  `json:"name"`
	Size               int64   `json:"size"`
	SHA256             *string `json:"sha256"`
	BrowserDownloadURL string  `json:"browser_download_url"`
}

// Release is one release of the repository the versioninfo document's releaseUrl belongs to, as its releases page lists it.
type Release struct {
	Tag         string         `json:"tag"`
	Name        string         `json:"name"`
	Prerelease  bool           `json:"prerelease"`
	PublishedAt string         `json:"published_at"`
	Author      string         `json:"author"`
	HTMLURL     string         `json:"html_url"`
	Body        string         `json:"body"`
	Assets      []ReleaseAsset `json:"assets"`
}

type githubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Prerelease  bool   `json:"prerelease"`
	PublishedAt string `json:"published_at"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	Author      struct {
		Login string `json:"login"`
	} `json:"author"`
	Assets []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// repositoryAPI answers the GitHub releases API URL of the repository a release page belongs to, false for any other host or shape.
func repositoryAPI(releaseURL string) (string, bool) {
	parsed, err := url.Parse(releaseURL)
	if err != nil || parsed.Host != "github.com" {
		return "", false
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(segments) < 2 || segments[0] == "" || segments[1] == "" {
		return "", false
	}
	return "https://api.github.com/repos/" + url.PathEscape(segments[0]) + "/" + url.PathEscape(segments[1]) +
		"/releases?per_page=" + strconv.Itoa(releasesPerPage), true
}

// Releases lists the releases of the repository releaseURL belongs to, newest first, each asset carrying the digest the release's SHA256SUMS.txt lists; nil while the list cannot be read.
func Releases(ctx context.Context, releaseURL string) []Release {
	api, ok := repositoryAPI(releaseURL)
	if !ok {
		return nil
	}
	reqCtx, cancel := context.WithTimeout(ctx, releasesTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, api, http.NoBody)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var listed []githubRelease
	if derr := json.NewDecoder(io.LimitReader(resp.Body, releaseBodyLimit)).Decode(&listed); derr != nil {
		return nil
	}
	releases := make([]Release, 0, len(listed))
	for i := range listed {
		releases = append(releases, releaseOf(ctx, &listed[i]))
	}
	return releases
}

func releaseOf(ctx context.Context, listed *githubRelease) Release {
	sums := map[string]string{}
	for _, asset := range listed.Assets {
		if asset.Name == checksumsName {
			if fetched, err := fetchChecksums(ctx, asset.BrowserDownloadURL); err == nil {
				sums = fetched
			}
			break
		}
	}
	assets := make([]ReleaseAsset, 0, len(listed.Assets))
	for _, asset := range listed.Assets {
		entry := ReleaseAsset{Name: asset.Name, Size: asset.Size, BrowserDownloadURL: asset.BrowserDownloadURL}
		if sum, ok := sums[asset.Name]; ok {
			entry.SHA256 = &sum
		}
		assets = append(assets, entry)
	}
	return Release{
		Tag:         listed.TagName,
		Name:        listed.Name,
		Prerelease:  listed.Prerelease,
		PublishedAt: listed.PublishedAt,
		Author:      listed.Author.Login,
		HTMLURL:     listed.HTMLURL,
		Body:        listed.Body,
		Assets:      assets,
	}
}
