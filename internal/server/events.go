package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

const (
	eventRetryMS       = 3000
	eventHeartbeat     = 25 * time.Second
	eventRingMaxEvents = 500
	eventRingMaxAge    = 5 * time.Minute
	eventBacklog       = 256
	eventStatsTimeout  = 30 * time.Second
)

var eventTopics = []string{"health", "tasks", "hosts", "admin", "monitoring", "profile", "notifications"}

const (
	eventTopicAdmin         = "admin"
	eventTopicProfile       = "profile"
	eventTopicNotifications = "notifications"
)

type eventEntry struct {
	id        string
	at        time.Time
	topic     string
	recipient string
	frame     []byte
}

type eventSubscriber struct {
	topics    map[string]bool
	principal string
	frames    chan []byte
}

func (e eventEntry) reaches(subscriber *eventSubscriber) bool {
	return subscriber.topics[e.topic] && (e.recipient == "" || e.recipient == subscriber.principal)
}

type eventHub struct {
	mu          sync.Mutex
	ring        []eventEntry
	subscribers map[*eventSubscriber]struct{}
	lastMS      int64
	seq         int
	floorID     string
}

type eventReady struct {
	ID     string   `json:"id"`
	Topics []string `json:"topics"`
}

type eventReset struct {
	Topics []string `json:"topics"`
}

func newEventHub() *eventHub {
	hub := &eventHub{subscribers: map[*eventSubscriber]struct{}{}}
	hub.floorID = hub.nextID()
	return hub
}

func (h *eventHub) nextID() string {
	now := time.Now().UnixMilli()
	if now < h.lastMS {
		now = h.lastMS
	}
	if now == h.lastMS {
		h.seq++
	} else {
		h.lastMS = now
		h.seq = 0
	}
	return formatEventID(now, h.seq)
}

func (h *eventHub) newestID() string {
	return formatEventID(h.lastMS, h.seq)
}

func (h *eventHub) oldestID() string {
	if len(h.ring) > 0 {
		return h.ring[0].id
	}
	return h.floorID
}

func formatEventID(ms int64, seq int) string {
	return strconv.FormatInt(ms, 10) + "-" + strconv.Itoa(seq)
}

func parseEventID(id string) (ms int64, seq int, ok bool) {
	head, tail, found := strings.Cut(id, "-")
	if !found {
		return 0, 0, false
	}
	ms, err := strconv.ParseInt(head, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	seq, err = strconv.Atoi(tail)
	if err != nil {
		return 0, 0, false
	}
	return ms, seq, true
}

func eventIDAfter(id, reference string) bool {
	ms, seq, _ := parseEventID(id)
	referenceMS, referenceSeq, _ := parseEventID(reference)
	if ms == referenceMS {
		return seq > referenceSeq
	}
	return ms > referenceMS
}

func eventFrame(id, event string, data any) ([]byte, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return []byte("id: " + id + "\nevent: " + event + "\ndata: " + string(raw) + "\n\n"), nil
}

func requestedEventTopics(query string, admin bool) map[string]bool {
	requested := map[string]bool{}
	for _, name := range strings.Split(query, ",") {
		name = strings.TrimSpace(name)
		for _, topic := range eventTopics {
			if name == topic {
				requested[topic] = true
			}
		}
	}
	if len(requested) == 0 {
		for _, topic := range eventTopics {
			requested[topic] = true
		}
	}
	if !admin {
		delete(requested, eventTopicAdmin)
	}
	return requested
}

func subscribedTopics(topics map[string]bool) []string {
	list := make([]string, 0, len(topics))
	for _, topic := range eventTopics {
		if topics[topic] {
			list = append(list, topic)
		}
	}
	return list
}

func (h *eventHub) trim() {
	cutoff := time.Now().Add(-eventRingMaxAge)
	for len(h.ring) > eventRingMaxEvents && h.ring[0].at.Before(cutoff) {
		h.ring = h.ring[1:]
	}
}

func (h *eventHub) publish(topic, event string, data any) {
	h.publishTo(topic, event, data, "")
}

func (h *eventHub) publishTo(topic, event string, data any, recipient string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	id := h.nextID()
	frame, err := eventFrame(id, event, data)
	if err != nil {
		slog.Error("serialize event", "topic", topic, "event", event, "error", err)
		return
	}
	entry := eventEntry{id: id, at: time.Now(), topic: topic, recipient: recipient, frame: frame}
	h.ring = append(h.ring, entry)
	h.trim()

	for subscriber := range h.subscribers {
		if !entry.reaches(subscriber) {
			continue
		}
		select {
		case subscriber.frames <- frame:
		default:
			delete(h.subscribers, subscriber)
			close(subscriber.frames)
		}
	}
}

func (h *eventHub) replay(subscriber *eventSubscriber, lastEventID string) [][]byte {
	if lastEventID == "" {
		return nil
	}
	_, _, valid := parseEventID(lastEventID)
	if !valid || eventIDAfter(h.oldestID(), lastEventID) || eventIDAfter(lastEventID, h.newestID()) {
		frame, err := eventFrame(h.nextID(), "reset", eventReset{Topics: subscribedTopics(subscriber.topics)})
		if err != nil {
			slog.Error("serialize event", "event", "reset", "error", err)
			return nil
		}
		return [][]byte{frame}
	}
	frames := [][]byte{}
	for i := range h.ring {
		if h.ring[i].reaches(subscriber) && eventIDAfter(h.ring[i].id, lastEventID) {
			frames = append(frames, h.ring[i].frame)
		}
	}
	return frames
}

func (h *eventHub) subscribe(topics map[string]bool, principal, lastEventID string) (*eventSubscriber, [][]byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	id := h.nextID()
	opening := [][]byte{}
	ready, err := eventFrame(id, "ready", eventReady{ID: id, Topics: subscribedTopics(topics)})
	if err != nil {
		slog.Error("serialize event", "event", "ready", "error", err)
	} else {
		retry := []byte("retry: " + strconv.Itoa(eventRetryMS) + "\n")
		opening = append(opening, append(retry, ready...))
	}
	subscriber := &eventSubscriber{topics: topics, principal: principal, frames: make(chan []byte, eventBacklog)}
	opening = append(opening, h.replay(subscriber, lastEventID)...)

	h.subscribers[subscriber] = struct{}{}
	return subscriber, opening
}

func (h *eventHub) unsubscribe(subscriber *eventSubscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, listed := h.subscribers[subscriber]; listed {
		delete(h.subscribers, subscriber)
		close(subscriber.frames)
	}
}

func (h *eventHub) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for subscriber := range h.subscribers {
		delete(h.subscribers, subscriber)
		close(subscriber.frames)
	}
}

func (s *Server) publishTask(task *tasks.Task) {
	s.events.publish("tasks", "task-updated", task)
	if taskFinished(task.Status) {
		s.publishHealth()
		if task.Notify {
			go s.notifyInbox(task)
		}
	}
}

func (s *Server) publishStats() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), eventStatsTimeout)
		defer cancel()
		s.events.publish("hosts", "stats-updated", s.statsDocument(ctx))
	}()
}

// @Summary		Event stream (server-sent events)
// @Description	Minimum role: viewer. The one event stream of the Universal Events Contract, plain WHATWG server-sent events. topics is a comma-separated list of health, tasks, hosts, admin, monitoring, profile and notifications; unknown names are ignored, an empty list asks for every topic, and the stream answers the topics the key's role may read, admin left out for a non-admin key, so the ready event's topics list is the subscription that stands; 403 only when nothing is left. The first frame is retry: 3000 followed by the ready event carrying the newest id and the subscribed topics. Every event carries id <epoch-ms>-<seq>, a kebab-case event name and one line of JSON data; a :hb comment line is sent after 25 seconds without a frame. Topic tasks sends task-updated, one task row as GET /api/tasks answers it, when a task is created and on every change of its status, progress_percent, progress_info or error_message. Topic hosts sends stats-updated, the GET /api/stats document, when a machine is created or removed and when one changes status. Topic health sends health, the GET /api/health report, whenever a task ends and the report differs from the last one sent. Topic admin sends restart-required, {required, last_modified_by, last_modified_time}, after every configuration save and backup restore, and {required: false} as the agent restarts; it is subscribed for an admin key alone. Topic monitoring sends cpu-sample {cpu: [sample]} with per_core_parsed, memory-sample {memory: [sample]} and network-sample {usage: [samples]}, the members GET /api/monitoring/system/cpu, /api/system/memory and /api/network/usage answer, whenever the collector takes them: on every collector tick while monitoring.storage_enabled, else only on POST /api/monitoring/collect. Topic profile sends profile-updated {} to the person whose preferences a PATCH /api/user/preferences changed, that person alone, on the stream and in a replay. Topic notifications sends unread-count {count} to the person whose inbox write the agent relayed to the identity provider, read back from the issuer after the write, that person alone. No topic has a snapshot event. The ring keeps the last 500 events or 5 minutes, whichever is larger: a Last-Event-ID inside it replays every later event of the subscribed topics, one outside it answers a reset event naming the subscribed topics. A task's output and every terminal stay on their WebSockets.
// @Tags			Status
// @Produce		text/event-stream
// @Param			topics			query	string	false	"Comma-separated topics: health, tasks, hosts, admin, monitoring, profile, notifications"
// @Param			Last-Event-ID	header	string	false	"The id of the last frame processed, sent on a reconnect only"
// @Success		200	"The stream"
// @Failure		401	{object}	problem.Body	"Missing credential"
// @Failure		403	{object}	problem.Body	"Invalid credential, or no requested topic the key may read"
// @Router			/api/events [get]
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	identity := auth.FromContext(r.Context())
	topics := requestedEventTopics(r.URL.Query().Get("topics"), identity != nil && identity.Role == "admin")
	if len(topics) == 0 {
		auth.WriteMsg(w, http.StatusForbidden, "None of the requested topics may be read with this key")
		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", "no-cache, no-transform")
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		slog.Warn("event stream flush unsupported", "error", err)
		return
	}

	subscriber, opening := s.events.subscribe(topics, s.personOf(identity), r.Header.Get("Last-Event-ID"))
	defer s.events.unsubscribe(subscriber)

	write := func(frame []byte) bool {
		if _, err := w.Write(frame); err != nil {
			return false
		}
		return controller.Flush() == nil
	}
	for _, frame := range opening {
		if !write(frame) {
			return
		}
	}

	heartbeat := time.NewTimer(eventHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case frame, open := <-subscriber.frames:
			if !open || !write(frame) {
				return
			}
			heartbeat.Reset(eventHeartbeat)
		case <-heartbeat.C:
			if !write([]byte(":hb\n\n")) {
				return
			}
			heartbeat.Reset(eventHeartbeat)
		}
	}
}
