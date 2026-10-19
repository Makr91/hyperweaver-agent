package server

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/Makr91/hyperweaver-agent/internal/certs"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// machineCredentialRef is one credentials[] entry of a machine's document: the vault row and the use it serves.
type machineCredentialRef struct {
	ID      string `json:"id"`
	Use     string `json:"use"`
	Default bool   `json:"default"`
}

// machineCredential is one credential as GET /api/machines/{name} answers it: the row's id, kind and name beside its use, never a member value.
type machineCredential struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Use     string `json:"use"`
	Default bool   `json:"default"`
}

var (
	errCredentialUnknown = errors.New("names no secret of this host")
	errCredentialKind    = errors.New("is not a password, ssh_key or key_pair row")
)

// credentialRefs reads the document's credentials[] entries.
func credentialRefs(config machines.MachineConfig) []machineCredentialRef {
	refs := []machineCredentialRef{}
	for _, entry := range config.List("credentials") {
		raw, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		var ref machineCredentialRef
		if uerr := json.Unmarshal(raw, &ref); uerr == nil && ref.ID != "" {
			refs = append(refs, ref)
		}
	}
	return refs
}

// defaultCredentialRefs answers machines.default_credentials as entries, each the default of its use, in use order.
func (s *Server) defaultCredentialRefs() []machineCredentialRef {
	uses := make([]string, 0, len(s.cfg.Machines.DefaultCredentials))
	for use, id := range s.cfg.Machines.DefaultCredentials {
		if id != "" {
			uses = append(uses, use)
		}
	}
	sort.Strings(uses)
	refs := make([]machineCredentialRef, 0, len(uses))
	for _, use := range uses {
		refs = append(refs, machineCredentialRef{ID: s.cfg.Machines.DefaultCredentials[use], Use: use, Default: true})
	}
	return refs
}

// credentialRow answers the vault row an id names when the reader may read it and its kind is a credential kind.
func (s *Server) credentialRow(ctx context.Context, id string, reader certs.Reader) (*certs.Row, error) {
	row, err := s.certs.Get(ctx, id)
	if errors.Is(err, certs.ErrNotFound) || (err == nil && !reader.MayRead(row)) {
		return nil, errCredentialUnknown
	}
	if err != nil {
		return nil, err
	}
	if !machines.CredentialKinds[row.Kind] {
		return nil, errCredentialKind
	}
	return row, nil
}

// machineRefs answers the machine's credential entries: the document's, else the host's defaults.
func (s *Server) machineRefs(machine *machines.Machine) []machineCredentialRef {
	refs := credentialRefs(machines.ParseConfiguration(machine))
	if len(refs) == 0 {
		return s.defaultCredentialRefs()
	}
	return refs
}

// machineCredentials answers the machine's credentials as the detail answers them, rows the reader may not read or that no longer exist dropped.
func (s *Server) machineCredentials(ctx context.Context, machine *machines.Machine, reader certs.Reader) []machineCredential {
	out := []machineCredential{}
	for _, ref := range s.machineRefs(machine) {
		row, err := s.credentialRow(ctx, ref.ID, reader)
		if err != nil {
			continue
		}
		out = append(out, machineCredential{ID: row.ID, Kind: row.Kind, Name: row.Name, Use: ref.Use, Default: ref.Default})
	}
	return out
}

// pickCredential answers the row a use signs in with: the explicit id when given, else the machine's default entry of the use, else its first entry of the use, else the host's default; nil when the machine names none, an error when a named row is unreadable or of another kind.
func (s *Server) pickCredential(ctx context.Context, machine *machines.Machine, reader certs.Reader, use, explicitID string) (*certs.Row, error) {
	if explicitID != "" {
		return s.credentialRow(ctx, explicitID, reader)
	}
	refs := s.machineRefs(machine)
	chosen := ""
	for _, ref := range refs {
		if ref.Use != use {
			continue
		}
		if ref.Default {
			chosen = ref.ID
			break
		}
		if chosen == "" {
			chosen = ref.ID
		}
	}
	if chosen == "" {
		return nil, nil
	}
	return s.credentialRow(ctx, chosen, reader)
}
