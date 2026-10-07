package server

import "time"

func (s *Server) liveIntervalSeconds() int64 {
	seconds, _ := s.cfg.Engine().GetAt("app", "/monitoring/live_interval").(int64)
	if seconds < 1 {
		seconds = int64(s.cfg.Monitoring.LiveInterval)
	}
	if seconds < 1 {
		seconds = 1
	}
	return seconds
}

func (s *Server) topicSubscribersChanged(topic string, _ bool) {
	if topic == eventTopicMonitoring {
		s.syncLiveSampling(false)
	}
}

func (s *Server) liveSamplingConfigSaved(name string) {
	if name == "app" {
		go s.syncLiveSampling(true)
	}
}

func (s *Server) syncLiveSampling(reread bool) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	wanted := s.events.subscriberCount(eventTopicMonitoring) > 0
	if !wanted {
		s.live.Stop()
		return
	}
	interval := time.Duration(s.liveIntervalSeconds()) * time.Second
	if reread && s.live.Running() && s.live.Interval() != interval {
		s.live.Stop()
	}
	s.live.Start(interval)
}

func (s *Server) stopLiveSampling() {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	s.live.Stop()
}
