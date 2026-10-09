package updater

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const assetProbeTimeout = 30 * time.Second

// Asset is one file of the release the versioninfo document names: its file name, its URL, its size in bytes and its SHA-256 from the release's checksums document, size and checksum null where unknown.
type Asset struct {
	Name     string  `json:"name"`
	URL      string  `json:"url"`
	Size     *int64  `json:"size"`
	Checksum *string `json:"checksum"`
}

// Assets lists the release's files from the document's platform URLs and checksumsUrl, one entry per URL the document carries, nil when it carries none.
func (i *Info) Assets(ctx context.Context) []Asset {
	urls := []string{i.WindowsURL, i.MacOSURL, i.LinuxURL, i.ChecksumsURL}
	sums := map[string]string{}
	if i.ChecksumsURL != "" {
		if fetched, err := fetchChecksums(ctx, i.ChecksumsURL); err == nil {
			sums = fetched
		}
	}
	var assets []Asset
	for _, assetURL := range urls {
		if assetURL == "" {
			continue
		}
		parsed, err := url.Parse(assetURL)
		if err != nil {
			continue
		}
		name := path.Base(parsed.Path)
		asset := Asset{Name: name, URL: assetURL, Size: assetSize(ctx, assetURL)}
		if sum, ok := sums[name]; ok {
			asset.Checksum = &sum
		}
		assets = append(assets, asset)
	}
	return assets
}

func assetSize(ctx context.Context, assetURL string) *int64 {
	reqCtx, cancel := context.WithTimeout(ctx, assetProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, assetURL, http.NoBody)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK || resp.ContentLength < 0 {
		return nil
	}
	size := resp.ContentLength
	return &size
}

// fetchChecksums reads the release's SHA256SUMS.txt as a file name to digest map.
func fetchChecksums(ctx context.Context, checksumsURL string) (map[string]string, error) {
	if checksumsURL == "" {
		return nil, errors.New("the versioninfo document carries no checksumsUrl — refusing an unverifiable update")
	}
	reqCtx, cancel := context.WithTimeout(ctx, assetProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, checksumsURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums fetch returned %s", resp.Status)
	}

	sums := map[string]string{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			sums[strings.TrimPrefix(fields[1], "*")] = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sums, nil
}
