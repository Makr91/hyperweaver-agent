package server

import (
	"github.com/Makr91/hyperweaver-agent/internal/configengine"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/updater"
	"github.com/Makr91/hyperweaver-agent/internal/version"
)

type restartRequiredEvent struct {
	Required         bool    `json:"required"`
	LastModifiedBy   *string `json:"last_modified_by,omitempty"`
	LastModifiedTime *string `json:"last_modified_time,omitempty"`
}

type updateAvailableEvent struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	ReleaseDate    any    `json:"release_date"`
}

type cpuSampleEvent struct {
	CPU []monitoring.CPUSample `json:"cpu"`
}

type memorySampleEvent struct {
	Memory []monitoring.MemorySample `json:"memory"`
}

type networkSampleEvent struct {
	Usage []monitoring.NetworkSample `json:"usage"`
}

func (s *Server) publishRestartRequired(_, _ string, status configengine.RestartStatus) {
	s.events.publish(eventTopicAdmin, "restart-required", restartRequiredEvent{
		Required:         status.RestartRequired,
		LastModifiedBy:   status.LastModifiedBy,
		LastModifiedTime: status.LastModifiedTime,
	})
}

func (s *Server) publishUnreadCount(person string, count int) {
	s.events.publishTo(eventTopicNotifications, "unread-count", unreadCountResponse{Count: count}, person)
}

func (s *Server) publishRestartCleared() {
	s.events.publish(eventTopicAdmin, "restart-required", restartRequiredEvent{Required: false})
}

func (s *Server) publishUpdateAvailable(info *updater.Info) {
	s.events.publish(eventTopicAdmin, "update-available", updateAvailableEvent{
		CurrentVersion: version.Version,
		LatestVersion:  info.Version,
		ReleaseDate:    nullable(info.ReleaseDate),
	})
}

func (s *Server) announceUpdate(info *updater.Info) {
	s.updateMu.Lock()
	if s.updateAnnounced == info.Version {
		s.updateMu.Unlock()
		return
	}
	s.updateAnnounced = info.Version
	s.updateMu.Unlock()
	s.publishUpdateAvailable(info)
	go s.notifyUpdateInbox(info.Version)
}

func (s *Server) publishSamples(cpu *monitoring.CPUSample, memory *monitoring.MemorySample, network []monitoring.NetworkSample) {
	if cpu != nil {
		s.events.publish("monitoring", "cpu-sample", cpuSampleEvent{CPU: []monitoring.CPUSample{*cpu}})
	}
	if memory != nil {
		s.events.publish("monitoring", "memory-sample", memorySampleEvent{Memory: []monitoring.MemorySample{*memory}})
	}
	if len(network) > 0 {
		s.events.publish("monitoring", "network-sample", networkSampleEvent{Usage: network})
	}
}
