// Package localclient builds the HTTP client the agent uses to call ITSELF
// over loopback: the bind-conflict probe, the wait-for-server poll, and the
// hwa:// protocol handoff. With ssl.enabled all traffic rides TLS (Mark's
// ruling, 2026-07-05), so this client trusts the agent's own certificate
// file as its root CA — real verification against the exact certificate the
// listener serves, never InsecureSkipVerify. When the certificate cannot be
// read (plain-HTTP configuration, or nothing generated yet) the default
// transport serves the http:// case.
package localclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Makr91/hyperweaver-agent/internal/safepath"
)

// New returns an HTTP client for the agent's own loopback origin, trusting
// every readable certificate among certPaths (the CA certificate for
// CA-signed server certs; the server certificate itself covers
// operator-provided material without a CA on disk).
func New(certPaths ...string) *http.Client {
	pool := x509.NewCertPool()
	trusted := false
	for _, certPath := range certPaths {
		clean, err := safepath.CleanAbs(certPath)
		if err != nil {
			continue
		}
		pemBytes, err := os.ReadFile(filepath.Clean(clean))
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(pemBytes) {
			trusted = true
		}
	}
	if !trusted {
		return &http.Client{}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}
