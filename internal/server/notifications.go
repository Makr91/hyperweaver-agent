package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/problem"
)

const (
	notificationsPath       = "/api/notifications"
	unreadCountTimeout      = 10 * time.Second
	pushNotConfiguredDetail = "Browser push is not offered by this agent; the identity provider's own push serves the estate"
)

type unreadCountResponse struct {
	Count int `json:"count"`
}

func notificationPath(r *http.Request, segments ...string) string {
	path := notificationsPath
	for _, segment := range segments {
		path += "/" + url.PathEscape(segment)
	}
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	return path
}

func (s *Server) pushUnreadCount(identity *auth.Identity) {
	ctx, cancel := context.WithTimeout(context.Background(), unreadCountTimeout)
	defer cancel()
	response, err := s.oidcMgr.IssuerRequest(ctx, http.MethodGet, notificationsPath+"/unread-count", http.NoBody, "")
	if err != nil {
		slog.Warn("unread count refresh failed", "error", err)
		return
	}
	defer func() {
		_ = response.Body.Close()
	}()
	var count unreadCountResponse
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, issuerBodyLimit)).Decode(&count) != nil {
		slog.Warn("unread count refresh answered no count", "status", response.StatusCode)
		return
	}
	s.publishUnreadCount(s.personOf(identity), count.Count)
}

func (s *Server) relayNotificationWrite(w http.ResponseWriter, r *http.Request, path string) {
	status, relayed := s.relayIssuer(w, r, path, http.NoBody)
	if relayed && status < http.StatusMultipleChoices {
		s.markUnread(false)
		s.pushUnreadCount(auth.FromContext(r.Context()))
	}
}

// @Summary		The signed-in person's inbox
// @Description	Minimum role: viewer. Relayed to the identity provider's GET /api/notifications under the bound account's token with page, size and unread_only passed through, the way a backend host proxies the hub; the issuer's status and body are answered as they came. A key no federated login minted answers 404, no valid token 503. The notifications token is listed in status.features only while such a token is held.
// @Tags			Local Login
// @Produce		json
// @Param			page		query	int		false	"Page number"
// @Param			size		query	int		false	"Page size"
// @Param			unread_only	query	bool	false	"Unread rows alone"
// @Success		200	{object}	map[string]interface{}	"The page: {items: [{id, title, body, type, severity, navigate, read_at, created_at}], page, size, total, total_pages}"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications [get]
func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	s.relayIssuer(w, r, notificationPath(r), http.NoBody)
}

// @Summary		The signed-in person's unread count
// @Description	Minimum role: viewer. Relayed to the identity provider's GET /api/notifications/unread-count under the bound account's token.
// @Tags			Local Login
// @Produce		json
// @Success		200	{object}	unreadCountResponse	"The count"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications/unread-count [get]
func (s *Server) handleUnreadCount(w http.ResponseWriter, r *http.Request) {
	s.relayIssuer(w, r, notificationPath(r, "unread-count"), http.NoBody)
}

// @Summary		Mark one notification read
// @Description	Minimum role: viewer. Relayed to the identity provider's POST /api/notifications/{id}/read; afterwards the unread count is read again and sent as unread-count on the notifications topic of the stream to this person.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login, or the issuer knows no such row"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications/{id}/read [post]
func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	s.relayNotificationWrite(w, r, notificationPath(r, r.PathValue("id"), "read"))
}

// @Summary		Mark one notification unread
// @Description	Minimum role: viewer. Relayed to the identity provider's POST /api/notifications/{id}/unread; the unread count follows on the stream.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login, or the issuer knows no such row"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications/{id}/unread [post]
func (s *Server) handleMarkNotificationUnread(w http.ResponseWriter, r *http.Request) {
	s.relayNotificationWrite(w, r, notificationPath(r, r.PathValue("id"), "unread"))
}

// @Summary		Mark every notification read
// @Description	Minimum role: viewer. Relayed to the identity provider's POST /api/notifications/read-all; the unread count follows on the stream.
// @Tags			Local Login
// @Success		204	"Marked"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications/read-all [post]
func (s *Server) handleMarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	s.relayNotificationWrite(w, r, notificationPath(r, "read-all"))
}

// @Summary		Delete one notification
// @Description	Minimum role: viewer. Relayed to the identity provider's DELETE /api/notifications/{id}; the unread count follows on the stream.
// @Tags			Local Login
// @Param			id	path	string	true	"The notification id"
// @Success		204	"Deleted"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login, or the issuer knows no such row"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications/{id} [delete]
func (s *Server) handleDeleteNotification(w http.ResponseWriter, r *http.Request) {
	s.relayNotificationWrite(w, r, notificationPath(r, r.PathValue("id")))
}

// @Summary		Clear the signed-in person's inbox
// @Description	Minimum role: viewer. Relayed to the identity provider's DELETE /api/notifications; the unread count follows on the stream.
// @Tags			Local Login
// @Success		204	"Cleared"
// @Failure		404	{object}	problem.Body	"The calling key was not minted by a federated login"
// @Failure		502	{object}	problem.Body	"Identity provider unreachable"
// @Failure		503	{object}	problem.Body	"No valid token for the bound account"
// @Router			/api/notifications [delete]
func (s *Server) handleDeleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	s.relayNotificationWrite(w, r, notificationPath(r))
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
