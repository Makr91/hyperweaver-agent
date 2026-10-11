package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/inbox"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

const (
	inboxNotifyPath   = "/api/notify"
	inboxTimeout      = 15 * time.Second
	hostPagePath      = "/hosts/self"
	updatePagePath    = "/hosts/self/agent/update"
	templatesPagePath = "/hosts/self/provisioning/templates"
)

type inboxNotification struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Navigate string `json:"navigate"`
	Tag      string `json:"tag"`
}

type inboxRecipient struct {
	UserUUID string `json:"user_uuid"`
}

type inboxWrite struct {
	IdempotencyKey string            `json:"idempotency_key"`
	Type           string            `json:"type"`
	Severity       string            `json:"severity"`
	Notification   inboxNotification `json:"notification"`
	Recipient      inboxRecipient    `json:"recipient"`
}

func taskOutcome(task *tasks.Task) string {
	switch task.Status {
	case tasks.StatusCompleted:
		return "finished"
	case tasks.StatusCompletedWithErrors:
		return "finished with errors"
	case tasks.StatusCancelled:
		return "was cancelled"
	default:
		return "failed"
	}
}

func taskTitle(task *tasks.Task) string {
	operation := strings.ReplaceAll(task.Operation, "_", " ")
	return strings.ToUpper(operation[:1]) + operation[1:] + " " + taskOutcome(task)
}

func isSystemTarget(name string) bool {
	return name == "" || name == "system" || name == "filesystem"
}

func taskBody(task *tasks.Task) string {
	body := "The " + strings.ReplaceAll(task.Operation, "_", " ")
	if isSystemTarget(task.MachineName) {
		body += " task " + taskOutcome(task) + "."
	} else {
		body += " task on " + task.MachineName + " " + taskOutcome(task) + "."
	}
	if task.ErrorMessage != nil && *task.ErrorMessage != "" {
		body += " " + *task.ErrorMessage
	}
	if len(body) > 1000 {
		body = body[:1000]
	}
	return body
}

func taskSeverity(task *tasks.Task) string {
	switch task.Status {
	case tasks.StatusCompleted:
		return "INFO"
	case tasks.StatusCompletedWithErrors, tasks.StatusCancelled:
		return "WARNING"
	default:
		return "DANGER"
	}
}

func taskNavigate(task *tasks.Task) string {
	if strings.HasPrefix(task.Operation, "template_") {
		return templatesPagePath
	}
	if isSystemTarget(task.MachineName) {
		return hostPagePath
	}
	return hostPagePath + "/machines/" + url.PathEscape(task.MachineName)
}

func taskWrite(task *tasks.Task) *inbox.Write {
	return &inbox.Write{
		IdempotencyKey: "hyperweaver-agent:task:" + task.ID,
		Type:           "SYSTEM",
		Severity:       taskSeverity(task),
		Title:          taskTitle(task),
		Body:           taskBody(task),
		Navigate:       taskNavigate(task),
		Tag:            "hyperweaver-agent-task",
	}
}

func updateWrite(latestVersion string) *inbox.Write {
	hostname, _ := os.Hostname()
	return &inbox.Write{
		IdempotencyKey: "hyperweaver-agent:update:" + latestVersion,
		Type:           "SYSTEM",
		Severity:       "INFO",
		Title:          "Hyperweaver Agent " + latestVersion + " is available",
		Body:           "Hyperweaver Agent " + latestVersion + " is published; " + hostname + " runs " + version.Version + ".",
		Navigate:       updatePagePath,
		Tag:            "hyperweaver-agent-update",
	}
}

func (s *Server) absoluteLink(path string) string {
	return strings.TrimSuffix(s.cfg.LocalURL(), "/") + path
}

func (s *Server) notifyInbox(task *tasks.Task) {
	write := taskWrite(task)
	for _, person := range s.personsOfKeyName(task.CreatedBy) {
		s.writeLocalInbox(person, write, "task_id", task.ID)
	}
	if s.writeProviderInbox(write, "task_id", task.ID) {
		slog.Info("task written to the person's inbox", "task_id", task.ID, "operation", task.Operation, "status", task.Status)
	}
}

func (s *Server) notifyUpdateInbox(latestVersion string) {
	write := updateWrite(latestVersion)
	for _, person := range s.personsOfActiveKeys() {
		s.writeLocalInbox(person, write, "latest_version", latestVersion)
	}
	if s.writeProviderInbox(write, "latest_version", latestVersion) {
		slog.Info("update written to the person's inbox", "current_version", version.Version, "latest_version", latestVersion)
	}
}

func (s *Server) writeLocalInbox(person string, write *inbox.Write, attrs ...any) {
	ctx, cancel := context.WithTimeout(context.Background(), inboxTimeout)
	defer cancel()
	if _, _, err := s.inbox.Create(ctx, person, write); err != nil {
		slog.Warn("local inbox write failed", append([]any{"error", err, "person", person}, attrs...)...)
	}
}

func (s *Server) writeProviderInbox(write *inbox.Write, attrs ...any) bool {
	subject := s.oidcMgr.BoundSubject()
	if subject == "" || s.oidcMgr.BearerToken() == "" {
		return false
	}
	raw, err := json.Marshal(inboxWrite{
		IdempotencyKey: write.IdempotencyKey,
		Type:           write.Type,
		Severity:       write.Severity,
		Notification: inboxNotification{
			Title:    write.Title,
			Body:     write.Body,
			Navigate: s.absoluteLink(write.Navigate),
			Tag:      write.Tag,
		},
		Recipient: inboxRecipient{UserUUID: subject},
	})
	if err != nil {
		slog.Warn("inbox write serialize failed", append([]any{"error", err}, attrs...)...)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), inboxTimeout)
	defer cancel()
	response, err := s.oidcMgr.IssuerRequest(ctx, http.MethodPost, inboxNotifyPath, bytes.NewReader(raw), "application/json")
	if err != nil {
		slog.Warn("inbox write failed", append([]any{"error", err}, attrs...)...)
		return false
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode >= http.StatusMultipleChoices {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		slog.Warn("inbox write refused", append([]any{"status", response.StatusCode, "detail", strings.TrimSpace(string(detail))}, attrs...)...)
		return false
	}
	return true
}

func (s *Server) publishInbox(person string, change inbox.Change) {
	s.events.publishTo(eventTopicNotifications, change.Event, change.Data, person)
	go s.publishUnread(person, change.Event == inbox.EventCreated)
}

func (s *Server) publishUnread(person string, created bool) {
	ctx, cancel := context.WithTimeout(context.Background(), inboxTimeout)
	defer cancel()
	count, err := s.unreadCount(ctx, person)
	if err != nil {
		slog.Warn("unread count read failed", "error", err, "person", person)
		return
	}
	s.publishUnreadCount(person, count)
	switch {
	case created:
		s.markUnread(true)
	case count == 0:
		s.markUnread(false)
	}
}
