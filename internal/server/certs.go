package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/certs"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

const (
	certForbiddenChange = "Only the person who shared it or a manager of the organization may change it."
	certNotFound        = "No such certificate."
	certRemoved         = "The certificate is removed."
)

// certWriteBody is the body of POST and PUT /api/certs: the row's own members and the record; is_public is read and never kept, no row of this host being public.
type certWriteBody struct {
	Organization string         `json:"organization"`
	Kind         string         `json:"kind"`
	Name         *string        `json:"name"`
	Published    *bool          `json:"published"`
	IsPublic     *bool          `json:"is_public"`
	GuestAccess  *bool          `json:"guest_access"`
	Record       map[string]any `json:"record"`
}

type certRemovedResponse struct {
	Message string `json:"message"`
}

func (s *Server) certReader(r *http.Request) certs.Reader {
	identity := auth.FromContext(r.Context())
	return certs.Reader{Persons: []string{s.personOf(identity)}, Admin: identity.Role == "admin"}
}

// secretRow answers the row the persons may read, the vault read a secret field's answer resolves through.
func (s *Server) secretRow(ctx context.Context, id string, persons []string) (*certs.Row, error) {
	row, err := s.certs.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !(certs.Reader{Persons: persons}).MayRead(row) {
		return nil, certs.ErrNotFound
	}
	return row, nil
}

// secretKindOf answers the kind of the row an id names, the check a secret field's answer passes at validation.
func (s *Server) secretKindOf(id string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), inboxTimeout)
	defer cancel()
	row, err := s.certs.Get(ctx, id)
	if err != nil {
		return "", false
	}
	return row.Kind, true
}

func (s *Server) readableCert(w http.ResponseWriter, r *http.Request) (*certs.Row, certs.Reader, bool) {
	reader := s.certReader(r)
	row, err := s.certs.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, certs.ErrNotFound) || (err == nil && !reader.MayRead(row)) {
		problem.Detail(w, http.StatusNotFound, certNotFound)
		return nil, reader, false
	}
	if err != nil {
		slog.Error("read certificate", "id", r.PathValue("id"), "error", err)
		problem.Detail(w, http.StatusInternalServerError, "The certificate could not be read")
		return nil, reader, false
	}
	return row, reader, true
}

// @Summary		The vault store's rows
// @Description	Minimum role: viewer. Every row of the store the calling key's person may read, newest first: an admin reads every row, a creator their own, every signed-in person a published row; no row of this host is is_public. kind narrows to one of the fourteen kinds, certificate, authority, request, key, ssh_certificate, template, password, api_key, basic_auth, key_pair, oauth_client, ssh_key, file and custom; organization narrows to the organization a row was shared under. The record is answered as it was sent, its created_by the row's creator.
// @Tags			Certificates
// @Produce		json
// @Param			kind			query	string	false	"One of the fourteen kinds"
// @Param			organization	query	string	false	"The organization the rows were shared under"
// @Success		200	{array}		certs.Row	"The rows"
// @Failure		422	{object}	problem.Body	"kind is not one of the fourteen"
// @Router			/api/certs [get]
func (s *Server) handleListCerts(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind != "" && !certs.ValidKind(kind) {
		problem.Invalid(w, problem.Enum("/kind", certs.Kinds...))
		return
	}
	rows, err := s.certs.List(r.Context(), s.certReader(r), kind, r.URL.Query().Get("organization"))
	if err != nil {
		slog.Error("list certificates", "error", err)
		problem.Detail(w, http.StatusInternalServerError, "The certificates could not be read")
		return
	}
	writeJSON(w, rows)
}

// @Summary		One row of the vault store
// @Description	Minimum role: viewer. The row, 404 when the person may not read it.
// @Tags			Certificates
// @Produce		json
// @Param			id	path	string	true	"The row id"
// @Success		200	{object}	certs.Row	"The row"
// @Failure		404	{object}	problem.Body	"No such certificate, or one the person may not read"
// @Router			/api/certs/{id} [get]
func (s *Server) handleGetCert(w http.ResponseWriter, r *http.Request) {
	row, _, ok := s.readableCert(w, r)
	if !ok {
		return
	}
	writeJSON(w, row)
}

// @Summary		Share a row to the vault store
// @Description	Minimum role: operator. Creates a row for the calling key's person in body.organization with the record as sent, created_by written onto it; subject and not_after are copied from record.facts; is_public is never kept. cert-updated with the row follows on the certs topic to every person who may read it.
// @Tags			Certificates
// @Accept			json
// @Produce		json
// @Param			body	body		certWriteBody	true	"The row: organization, kind, name, published, guest_access and record"
// @Success		201	{object}	certs.Row	"The row"
// @Failure		400	{object}	problem.Body	"Unreadable body"
// @Failure		422	{object}	problem.Body	"kind is not one of the fourteen"
// @Router			/api/certs [post]
func (s *Server) handleCreateCert(w http.ResponseWriter, r *http.Request) {
	var body certWriteBody
	if err := decodeBody(r, &body); err != nil {
		problem.BadRequest(w)
		return
	}
	if !certs.ValidKind(body.Kind) {
		problem.Invalid(w, problem.Enum("/kind", certs.Kinds...))
		return
	}
	write := &certs.Write{Organization: body.Organization, Kind: body.Kind, Record: body.Record}
	if body.Name != nil {
		write.Name = *body.Name
	}
	if body.Published != nil {
		write.Published = *body.Published
	}
	if body.GuestAccess != nil {
		write.GuestAccess = *body.GuestAccess
	}
	row, err := s.certs.Create(r.Context(), s.personOf(auth.FromContext(r.Context())), write)
	if err != nil {
		slog.Error("create certificate", "error", err)
		problem.Detail(w, http.StatusInternalServerError, "The certificate could not be stored")
		return
	}
	writeJSONStatus(w, http.StatusCreated, row)
}

// @Summary		Change a row of the vault store
// @Description	Minimum role: operator. Sets any of name, published and guest_access and replaces the record when the body carries one; is_public is never kept. 404 when the person may not read the row, 403 when they may not change it, the creator and an admin alone. cert-updated follows on the certs topic.
// @Tags			Certificates
// @Accept			json
// @Produce		json
// @Param			id		path	string			true	"The row id"
// @Param			body	body	certWriteBody	true	"The members to set"
// @Success		200	{object}	certs.Row	"The row"
// @Failure		403	{object}	problem.Body	"Only the person who shared it or a manager of the organization may change it."
// @Failure		404	{object}	problem.Body	"No such certificate."
// @Router			/api/certs/{id} [put]
func (s *Server) handleUpdateCert(w http.ResponseWriter, r *http.Request) {
	var body certWriteBody
	if err := decodeBody(r, &body); err != nil {
		problem.BadRequest(w)
		return
	}
	row, reader, ok := s.readableCert(w, r)
	if !ok {
		return
	}
	if !reader.MayManage(row) {
		problem.Detail(w, http.StatusForbidden, certForbiddenChange)
		return
	}
	updated, err := s.certs.Update(r.Context(), row, &certs.Patch{
		Name: body.Name, Published: body.Published, GuestAccess: body.GuestAccess, Record: body.Record,
	})
	if err != nil {
		slog.Error("update certificate", "id", row.ID, "error", err)
		problem.Detail(w, http.StatusInternalServerError, "The certificate could not be stored")
		return
	}
	writeJSON(w, updated)
}

// @Summary		Remove a row from the vault store
// @Description	Minimum role: operator. Removes the row; every other row and every person's pulled copy stay. 404 when the person may not read it, 403 when they may not change it. cert-removed {id, organization} follows on the certs topic.
// @Tags			Certificates
// @Produce		json
// @Param			id	path	string	true	"The row id"
// @Success		200	{object}	certRemovedResponse	"The certificate is removed."
// @Failure		403	{object}	problem.Body	"Only the person who shared it or a manager of the organization may change it."
// @Failure		404	{object}	problem.Body	"No such certificate."
// @Router			/api/certs/{id} [delete]
func (s *Server) handleDeleteCert(w http.ResponseWriter, r *http.Request) {
	row, reader, ok := s.readableCert(w, r)
	if !ok {
		return
	}
	if !reader.MayManage(row) {
		problem.Detail(w, http.StatusForbidden, certForbiddenChange)
		return
	}
	if err := s.certs.Delete(r.Context(), row); err != nil {
		slog.Error("delete certificate", "id", row.ID, "error", err)
		problem.Detail(w, http.StatusInternalServerError, "The certificate could not be removed")
		return
	}
	writeJSON(w, certRemovedResponse{Message: certRemoved})
}
