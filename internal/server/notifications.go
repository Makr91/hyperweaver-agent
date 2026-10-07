package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/inbox"
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
	Items      []*inbox.Row `json:"items"`
	Page       int          `json:"page"`
	Size       int          `json:"size"`
	Total      int          `json:"total"`
	TotalPages int          `json:"total_pages"`
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
		return
	case err != nil:
		slog.Error("inbox write failed", "error", err, "person", person, "path", r.URL.Path)
		problem.Detail(w, http.StatusInternalServerError, "The inbox could not be written")
		return
	}
	w.WriteHeader(http.StatusNoContent)
	count, cerr := s.inbox.UnreadCount(r.Context(), person)
	if cerr != nil {
		slog.Warn("unread count read failed", "error", cerr, "person", person)
		return
	}
	s.publishUnreadCount(person, count)
	if count == 0 {
		s.markUnread(false)
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

// @Summary		The signed-in person's inbox
// @Description	Minimum role: viewer. One page of the local inbox of the person the calling key stands for, newest first: page counts from 0, size is 20 unless given and at most 100, and unread_only keeps the unread rows alone.
// @Tags			Local Login
// @Produce		json
// @Param			page		query	int		false	"Page number, counted from 0"
// @Param			size		query	int		false	"Page size, 20 unless given, at most 100"
// @Param			unread_only	query	bool	false	"Unread rows alone"
// @Success		200	{object}	notificationsPage	"The page: {items: [{id, title, body, type, severity, navigate, read_at, created_at}], page, size, total, total_pages}"
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
	rows, total, err := s.inbox.List(r.Context(), person, page, size, unreadOnly)
	if err != nil {
		slog.Error("inbox list failed", "error", err, "person", person)
		problem.Detail(w, http.StatusInternalServerError, "The inbox could not be read")
		return
	}
	writeJSON(w, notificationsPage{
		Items:      rows,
		Page:       page,
		Size:       size,
		Total:      total,
		TotalPages: (total + size - 1) / size,
	})
}

// @Summary		The signed-in person's unread count
// @Description	Minimum role: viewer. How many rows of the person's local inbox are unread.
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
	count, err := s.inbox.UnreadCount(r.Context(), person)
	if err != nil {
		slog.Error("unread count read failed", "error", err, "person", person)
		problem.Detail(w, http.StatusInternalServerError, "The inbox could not be read")
		return
	}
	writeJSON(w, unreadCountResponse{Count: count})
}

// @Summary		Mark one notification read
// @Description	Minimum role: viewer. Records the person's local inbox row as read; the unread count follows as unread-count on the notifications topic of the stream to this person.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"No such row in the person's inbox"
// @Router			/api/notifications/{id}/read [post]
func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	s.inboxWritten(w, r, person, s.inbox.MarkRead(r.Context(), person, r.PathValue("id")))
}

// @Summary		Mark one notification unread
// @Description	Minimum role: viewer. Puts the person's local inbox row back to unread; the unread count follows on the stream.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"No such row in the person's inbox"
// @Router			/api/notifications/{id}/unread [post]
func (s *Server) handleMarkNotificationUnread(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	s.inboxWritten(w, r, person, s.inbox.MarkUnread(r.Context(), person, r.PathValue("id")))
}

// @Summary		Mark every notification read
// @Description	Minimum role: viewer. Records every unread row of the person's local inbox as read; the unread count follows on the stream.
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
	s.inboxWritten(w, r, person, s.inbox.MarkAllRead(r.Context(), person))
}

// @Summary		Delete one notification
// @Description	Minimum role: viewer. Removes the row from the person's local inbox; the unread count follows on the stream.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Deleted"
// @Failure		404	{object}	problem.Body	"No such row in the person's inbox"
// @Router			/api/notifications/{id} [delete]
func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	person, ok := s.inboxPerson(w, r)
	if !ok {
		return
	}
	s.inboxWritten(w, r, person, s.inbox.Delete(r.Context(), person, r.PathValue("id")))
}

// @Summary		Clear the signed-in person's inbox
// @Description	Minimum role: viewer. Removes every row of the person's local inbox; the unread count follows on the stream.
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
