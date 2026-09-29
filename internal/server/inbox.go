package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

const (
	inboxNotifyPath = "/api/notify"
	inboxTimeout    = 15 * time.Second
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

func taskTitle(task *tasks.Task) string {
	operation := strings.ReplaceAll(task.Operation, "_", " ")
	switch task.Status {
	case tasks.StatusCompleted:
		return strings.ToUpper(operation[:1]) + operation[1:] + " finished"
	case tasks.StatusCompletedWithErrors:
		return strings.ToUpper(operation[:1]) + operation[1:] + " finished with errors"
	case tasks.StatusCancelled:
		return strings.ToUpper(operation[:1]) + operation[1:] + " cancelled"
	default:
		return strings.ToUpper(operation[:1]) + operation[1:] + " failed"
	}
}

func taskBody(task *tasks.Task) string {
	body := task.MachineName
	if task.ErrorMessage != nil && *task.ErrorMessage != "" {
		body += ": " + *task.ErrorMessage
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

func (s *Server) taskNavigate(task *tasks.Task) string {
	base := s.cfg.LocalURL()
	if task.MachineName == "" || task.MachineName == "system" || task.MachineName == "filesystem" {
		return base
	}
	return base + "hosts/self/machines/" + url.PathEscape(task.MachineName)
}

func (s *Server) notifyInbox(task *tasks.Task) {
	subject := s.oidcMgr.BoundSubject()
	if subject == "" || s.oidcMgr.BearerToken() == "" {
		return
	}
	write := inboxWrite{
		IdempotencyKey: "hyperweaver-agent:task:" + task.ID,
		Type:           "SYSTEM",
		Severity:       taskSeverity(task),
		Notification: inboxNotification{
			Title:    taskTitle(task),
			Body:     taskBody(task),
			Navigate: s.taskNavigate(task),
			Tag:      "hyperweaver-agent-task",
		},
		Recipient: inboxRecipient{UserUUID: subject},
	}
	raw, err := json.Marshal(write)
	if err != nil {
		slog.Warn("inbox write serialize failed", "error", err, "task_id", task.ID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), inboxTimeout)
	defer cancel()
	response, err := s.oidcMgr.IssuerRequest(ctx, http.MethodPost, inboxNotifyPath, bytes.NewReader(raw), "application/json")
	if err != nil {
		slog.Warn("inbox write failed", "error", err, "task_id", task.ID)
		return
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode >= http.StatusMultipleChoices {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		slog.Warn("inbox write refused", "status", response.StatusCode, "task_id", task.ID, "detail", strings.TrimSpace(string(detail)))
		return
	}
	slog.Info("task written to the person's inbox", "task_id", task.ID, "operation", task.Operation, "status", task.Status)
}
