package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/inbox"
	"github.com/Makr91/hyperweaver-agent/internal/oidc"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

const (
	notificationsDefaultSize = 20
	notificationsMaxSize     = 100
	pushNotConfiguredDetail  = "Browser push is not offered by this agent; the identity provider's own push serves the estate"
)

type unreadCountResponse struct {
	Count int `json:"count"`
}

type notificationsPage struct {
	Items      []any `json:"items"`
	Page       int   `json:"page"`
	Size       int   `json:"size"`
	Total      int   `json:"total"`
	TotalPages int   `json:"total_pages"`
}

type inboxEntry struct {
	at   time.Time
	item any
}

func (s *Server) inboxPerson(w http.ResponseWriter, r *http.Request) (person string, ok bool) {
	person = s.personOf(auth.FromContext(r.Context()))
	if person == "" {
		problem.Detail(w, http.StatusInternalServerError, "The calling key stands for no person")
		return "", false
	}
	return person, true
}

func (s *Server) inboxWritten(w http.ResponseWriter, r *http.Request, person string, err error) {
	switch {
	case errors.Is(err, inbox.ErrNotFound):
		problem.NotFound(w)
	case err != nil:
		slog.Error("inbox write failed", "error", err, "person", person, "path", r.URL.Path)
		problem.Detail(w, http.StatusInternalServerError, "The inbox could not be written")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) hubWritten(w http.ResponseWriter, r *http.Request, person, method, path string, change inbox.Change) {
	status, err := s.hubCall(r.Context(), method, path, nil)
	switch {
	case errors.Is(err, oidc.ErrNoToken):
		problem.Detail(w, http.StatusServiceUnavailable, "The agent holds no valid token for the bound account; sign in again")
	case err != nil:
		slog.Warn("hub inbox write failed", "error", err, "path", path)
		problem.Detail(w, http.StatusBadGateway, "Identity provider unreachable: "+err.Error())
	case status == http.StatusNotFound:
		problem.NotFound(w)
	case status >= http.StatusMultipleChoices:
		problem.Detail(w, http.StatusBadGateway, fmt.Sprintf("The identity provider answered HTTP %d", status))
	default:
		w.WriteHeader(http.StatusNoContent)
		if !s.hubLive() {
			s.publishInbox(person, change)
		}
	}
}

func (s *Server) hubAll(r *http.Request, person, method, path string) {
	if !s.hubPerson(person) {
		return
	}
	status, err := s.hubCall(r.Context(), method, path, nil)
	if err != nil || status >= http.StatusMultipleChoices {
		slog.Warn("hub inbox write failed", "error", err, "status", status, "path", path)
	}
}

func pageParams(r *http.Request) (page, size int) {
	query := r.URL.Query()
	page, _ = strconv.Atoi(query.Get("page"))
	if page < 0 {
		page = 0
	}
	size, _ = strconv.Atoi(query.Get("size"))
	if size < 1 {
		size = notificationsDefaultSize
	}
	if size > notificationsMaxSize {
		size = notificationsMaxSize
	}
	return page, size
}

func hubCreatedAt(item map[string]any) time.Time {
	raw, _ := item["created_at"].(string)
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

// @Summary		The signed-in person's inbox
// @Description	Minimum role: viewer. One page of the inbox of the person the calling key stands for, newest first: page counts from 0, size is 20 unless given and at most 100, and unread_only keeps the unread rows alone. The rows are the agent's local inbox, origin local, and, for the account the agent is bound to while it holds that account's token, the identity provider's hub rows, origin hub, each keeping the hub's own numeric id; total counts both.
// @Tags			Local Login
// @Produce		json
// @Param			page		query	int		false	"Page number, counted from 0"
// @Param			size		query	int		false	"Page size, 20 unless given, at most 100"
// @Param			unread_only	query	bool	false	"Unread rows alone"
// @Success		200	{object}	notificationsPage	"The page: {items: [{id, title, body, type, severity, navigate, read_at, created_at, origin}], page, size, total, total_pages}; a hub row carries every member the hub answers"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential"
// @Router			/api/notifications [get]
func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	page, size := pageParams(r)
	unreadOnly, _ := strconv.ParseBool(r.URL.Query().Get("unread_only"))
	want := (page + 1) * size
	rows, total, err := s.inbox.List(r.Context(), person, 0, want, unreadOnly)
	if err != nil {
		slog.Error("inbox list failed", "error", err, "person", person)
		problem.Detail(w, http.StatusInternalServerError, "The inbox could not be read")
		return
	}
	entries := make([]inboxEntry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, inboxEntry{at: row.CreatedAt, item: row})
	}
	if s.hubPerson(person) {
		hubRows, hubTotal, herr := s.hubRows(r.Context(), want, unreadOnly)
		if herr != nil {
			slog.Warn("hub inbox read failed", "error", herr, "person", person)
		} else {
			total += hubTotal
			for _, item := range hubRows {
				entries = append(entries, inboxEntry{at: hubCreatedAt(item), item: item})
			}
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].at.After(entries[j].at) })
	start := page * size
	if start > len(entries) {
		start = len(entries)
	}
	end := start + size
	if end > len(entries) {
		end = len(entries)
	}
	items := make([]any, 0, end-start)
	for _, entry := range entries[start:end] {
		items = append(items, entry.item)
	}
	writeJSON(w, notificationsPage{
		Items:      items,
		Page:       page,
		Size:       size,
		Total:      total,
		TotalPages: (total + size - 1) / size,
	})
}

// @Summary		The signed-in person's unread count
// @Description	Minimum role: viewer. How many rows of the person's inbox are unread, the local rows and, for the bound account while its token is held, the hub's.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	unreadCountResponse	"The count"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential"
// @Router			/api/notifications/unread-count [get]
func (s *Server) handleUnreadCount(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	count, err := s.unreadCount(r.Context(), person)
	if err != nil {
		slog.Error("unread count read failed", "error", err, "person", person)
		problem.Detail(w, http.StatusInternalServerError, "The inbox could not be read")
		return
	}
	writeJSON(w, unreadCountResponse{Count: count})
}

// @Summary		Mark one notification read
// @Description	Minimum role: viewer. Records the row as read: a local row in the agent's store, a hub row (a numeric id) forwarded to the identity provider. notification-read {id, read_at} and then unread-count follow on the notifications topic of the stream to this person.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"No such row in the person's inbox"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Router			/api/notifications/{id}/read [post]
func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if isHubID(id) && s.hubPerson(person) {
		s.hubWritten(w, r, person, http.MethodPost, hubNotificationsPath+"/"+id+"/read", inbox.Change{
			Event: inbox.EventRead, Data: inbox.ReadChange{ID: json.Number(id), ReadAt: time.Now().UTC()},
		})
		return
	}
	s.inboxWritten(w, r, person, s.inbox.MarkRead(r.Context(), person, id))
}

// @Summary		Mark one notification unread
// @Description	Minimum role: viewer. Puts the row back to unread, a hub row forwarded to the identity provider; notification-unread {id} and then unread-count follow on the stream.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"No such row in the person's inbox"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Router			/api/notifications/{id}/unread [post]
func (s *Server) handleMarkNotificationUnread(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if isHubID(id) && s.hubPerson(person) {
		s.hubWritten(w, r, person, http.MethodPost, hubNotificationsPath+"/"+id+"/unread", inbox.Change{
			Event: inbox.EventUnread, Data: inbox.IDChange{ID: json.Number(id)},
		})
		return
	}
	s.inboxWritten(w, r, person, s.inbox.MarkUnread(r.Context(), person, id))
}

// @Summary		Mark every notification read
// @Description	Minimum role: viewer. Records every unread row as read, the hub's forwarded to the identity provider first for the bound account; inbox-read-all {read_at} and then unread-count follow on the stream.
// @Tags			Local Login
// @Success		204	"Marked"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential"
// @Router			/api/notifications/read-all [post]
func (s *Server) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	s.hubAll(r, person, http.MethodPost, hubNotificationsPath+"/read-all")
	s.inboxWritten(w, r, person, s.inbox.MarkAllRead(r.Context(), person))
}

// @Summary		Delete one notification
// @Description	Minimum role: viewer. Removes the row, a hub row dismissed at the identity provider; notification-dismissed {id} and then unread-count follow on the stream.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Deleted"
// @Failure		404	{object}	problem.Body	"No such row in the person's inbox"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Router			/api/notifications/{id} [delete]
func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if isHubID(id) && s.hubPerson(person) {
		s.hubWritten(w, r, person, http.MethodDelete, hubNotificationsPath+"/"+id, inbox.Change{
			Event: inbox.EventDismissed, Data: inbox.IDChange{ID: json.Number(id)},
		})
		return
	}
	s.inboxWritten(w, r, person, s.inbox.Delete(r.Context(), person, id))
}

// @Summary		Clear the signed-in person's inbox
// @Description	Minimum role: viewer. Removes every row, the hub's cleared at the identity provider first for the bound account; inbox-cleared {} and then unread-count follow on the stream.
// @Tags			Local Login
// @Success		204	"Cleared"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential"
// @Router			/api/notifications [delete]
func (s *Server) handleDeleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	s.hubAll(r, person, http.MethodDelete, hubNotificationsPath)
	s.inboxWritten(w, r, person, s.inbox.DeleteAll(r.Context(), person))
}

// @Summary		Browser push is not offered
// @Description	Minimum role: viewer. This agent signs no browser push of its own: the identity provider's push reaches the person on every host, so the VAPID key, the subscription routes and the test toast answer 503 not-configured, and the shared UI's notifications switch stays off here.
// @Tags			Local Login
// @Produce		json
// @Failure		503	{object}	problem.Body	"Push is not offered by this agent"
// @Router			/api/notifications/vapid-key [get]
func (s *Server) handlePushNotConfigured(w http.ResponseWriter, _ *http.Request) {
	problem.Detail(w, http.StatusServiceUnavailable, pushNotConfiguredDetail)
}
