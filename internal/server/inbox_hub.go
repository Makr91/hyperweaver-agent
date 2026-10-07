package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/inbox"
	"github.com/Makr91/hyperweaver-agent/internal/oidc"
)

const (
	hubNotificationsPath = "/api/notifications"
	hubStreamPath        = "/api/events?topics=session,notifications"
	hubPageSize          = 100
	originHub            = "hub"
	hubStreamFirstDelay  = 3 * time.Second
	hubStreamMaxDelay    = 30 * time.Second
	hubFrameLimit        = 1 << 20
)

type hubStream struct {
	mu      sync.Mutex
	base    context.Context
	stopAll context.CancelFunc
	cancel  context.CancelFunc
	live    bool
}

var errGrantEnded = errors.New("the identity provider ended the bound account's grant")

func (s *Server) hubLive() bool {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	return s.hub.live
}

func (s *Server) setHubLive(live bool) {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.hub.live = live
}

func newHubStream() *hubStream {
	base, stopAll := context.WithCancel(context.Background())
	return &hubStream{base: base, stopAll: stopAll}
}

type hubPage struct {
	Items      []map[string]any `json:"items"`
	Total      json.Number      `json:"total"`
	TotalPages json.Number      `json:"total_pages"`
}

type hubCount struct {
	Count json.Number `json:"count"`
}

func (s *Server) hubPerson(person string) bool {
	bound := s.oidcMgr.BoundEmail()
	return bound != "" && person == bound && s.oidcMgr.BearerToken() != ""
}

func isHubID(id string) bool {
	_, err := strconv.ParseInt(id, 10, 64)
	return err == nil
}

func (s *Server) hubCall(ctx context.Context, method, path string, out any) (status int, err error) {
	response, rerr := s.oidcMgr.IssuerRequest(ctx, method, path, http.NoBody, "")
	if rerr != nil {
		return 0, rerr
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode >= http.StatusMultipleChoices || out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, issuerBodyLimit))
		return response.StatusCode, nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, issuerBodyLimit))
	decoder.UseNumber()
	return response.StatusCode, decoder.Decode(out)
}

func (s *Server) hubUnreadCount(ctx context.Context) (int, error) {
	var answer hubCount
	status, err := s.hubCall(ctx, http.MethodGet, hubNotificationsPath+"/unread-count", &answer)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("the identity provider answered the unread count with HTTP %d", status)
	}
	return strconv.Atoi(answer.Count.String())
}

func (s *Server) unreadCount(ctx context.Context, person string) (int, error) {
	count, err := s.inbox.UnreadCount(ctx, person)
	if err != nil {
		return 0, err
	}
	if s.hubPerson(person) {
		hub, herr := s.hubUnreadCount(ctx)
		if herr != nil {
			slog.Warn("hub unread count read failed", "error", herr, "person", person)
			return count, nil
		}
		count += hub
	}
	return count, nil
}

func (s *Server) hubRows(ctx context.Context, want int, unreadOnly bool) (rows []map[string]any, total int, err error) {
	rows = []map[string]any{}
	for page := 0; len(rows) < want; page++ {
		path := hubNotificationsPath + "?page=" + strconv.Itoa(page) + "&size=" + strconv.Itoa(hubPageSize)
		if unreadOnly {
			path += "&unread_only=true"
		}
		var answer hubPage
		status, cerr := s.hubCall(ctx, http.MethodGet, path, &answer)
		if cerr != nil {
			return nil, 0, cerr
		}
		if status != http.StatusOK {
			return nil, 0, fmt.Errorf("the identity provider answered the inbox with HTTP %d", status)
		}
		answered, terr := strconv.Atoi(answer.Total.String())
		if terr != nil {
			return nil, 0, terr
		}
		pages, perr := strconv.Atoi(answer.TotalPages.String())
		if perr != nil {
			return nil, 0, perr
		}
		total = answered
		for _, item := range answer.Items {
			item["origin"] = originHub
			rows = append(rows, item)
		}
		if page+1 >= pages || len(answer.Items) == 0 {
			break
		}
	}
	return rows, total, nil
}

func (s *Server) publishHubUnread(person string) {
	ctx, cancel := context.WithTimeout(context.Background(), inboxTimeout)
	defer cancel()
	count, err := s.unreadCount(ctx, person)
	if err != nil {
		slog.Warn("unread count read failed", "error", err, "person", person)
		return
	}
	s.publishUnreadCount(person, count)
	s.markUnread(count > 0)
}

func (s *Server) syncHubStream() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	wanted := s.events.subscriberCount(eventTopicNotifications) > 0 &&
		s.oidcMgr.BoundEmail() != "" && s.oidcMgr.BearerToken() != ""
	switch {
	case wanted && s.hub.cancel == nil && s.hub.base.Err() == nil:
		ctx, cancel := context.WithCancel(s.hub.base)
		s.hub.cancel = cancel
		go s.runHubStream(ctx, cancel)
	case !wanted && s.hub.cancel != nil:
		s.hub.cancel()
		s.hub.cancel = nil
	}
}

func (s *Server) stopHubStream() {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	s.hub.stopAll()
	s.hub.cancel = nil
}

func (s *Server) endHubStream(ctx context.Context, cancel context.CancelFunc) {
	s.hub.mu.Lock()
	defer s.hub.mu.Unlock()
	if ctx.Err() == nil {
		s.hub.cancel = nil
	}
	cancel()
}

func (s *Server) runHubStream(ctx context.Context, cancel context.CancelFunc) {
	defer s.endHubStream(ctx, cancel)
	delay := hubStreamFirstDelay
	lastID := ""
	for {
		opened, refusal := s.readHubStream(ctx, &lastID)
		if refusal != nil {
			slog.Warn("the identity provider's notifications stream is not relayed", "error", refusal)
			return
		}
		if ctx.Err() != nil {
			return
		}
		if opened {
			delay = hubStreamFirstDelay
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > hubStreamMaxDelay {
			delay = hubStreamMaxDelay
		}
	}
}

func (s *Server) readHubStream(ctx context.Context, lastID *string) (opened bool, refusal error) {
	response, err := s.oidcMgr.IssuerStream(ctx, hubStreamPath, *lastID)
	if errors.Is(err, oidc.ErrNoToken) {
		return false, err
	}
	if err != nil {
		slog.Debug("hub notifications stream dropped", "error", err)
		return false, nil
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return false, fmt.Errorf("the identity provider answered the stream with HTTP %d", response.StatusCode)
	}
	if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		return false, errors.New("the identity provider answered the stream with " + response.Header.Get("Content-Type"))
	}
	slog.Info("hub notifications stream relayed")
	s.setHubLive(true)
	defer s.setHubLive(false)
	person := s.oidcMgr.BoundEmail()
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), hubFrameLimit)
	var id, event string
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if !s.relayHubFrame(person, event, data.String()) {
				s.oidcMgr.EndGrant()
				return true, errGrantEnded
			}
			if id != "" {
				*lastID = id
			}
			id, event = "", ""
			data.Reset()
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "id":
			id = value
		case "event":
			event = value
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
		}
	}
	return true, nil
}

func (s *Server) relayHubFrame(person, event, data string) bool {
	switch event {
	case "":
		return true
	case "session-terminated":
		return false
	case "ready", "reset", "unread-count":
		go s.publishHubUnread(person)
		return true
	case inbox.EventCreated:
		decoder := json.NewDecoder(strings.NewReader(data))
		decoder.UseNumber()
		row := map[string]any{}
		if err := decoder.Decode(&row); err != nil {
			return true
		}
		row["origin"] = originHub
		s.events.publishTo(eventTopicNotifications, event, row, person)
		return true
	}
	if json.Valid([]byte(data)) {
		s.events.publishTo(eventTopicNotifications, event, json.RawMessage(data), person)
	}
	return true
}
