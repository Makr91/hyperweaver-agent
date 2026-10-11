package server

const (
	eventTopicSessions   = "sessions"
	eventSessionStarted  = "session-started"
	eventSessionEnded    = "session-ended"
	sessionKindHostShell = "host_shell"
	sessionKindSSH       = "ssh"
)

type sessionEvent struct {
	Kind        string `json:"kind"`
	ID          string `json:"id"`
	MachineName string `json:"machine_name"`
}

func (s *Server) publishSession(event, kind, id, machine, person string) {
	s.events.publishTo(eventTopicSessions, event, sessionEvent{Kind: kind, ID: id, MachineName: machine}, person)
}

func (s *Server) endTermSession(id string) {
	if session, ended := s.termSessions.close(id); ended {
		s.publishSession(eventSessionEnded, sessionKindHostShell, session.ID, "", session.person)
	}
}

func (s *Server) endSSHSession(id string) {
	if session, ended := s.sshSessions.close(id); ended {
		s.publishSession(eventSessionEnded, sessionKindSSH, session.ID, session.MachineName, session.person)
	}
}

func (s *Server) endIdleSessionsOfKey(createdBy string) {
	for _, session := range s.termSessions.idleOf(createdBy) {
		s.endTermSession(session.ID)
	}
	for _, session := range s.sshSessions.idleOf(createdBy) {
		s.endSSHSession(session.ID)
	}
}

func (s *Server) endAllSessions() {
	for _, session := range s.termSessions.snapshot() {
		s.endTermSession(session.ID)
	}
	for _, session := range s.sshSessions.snapshot() {
		s.endSSHSession(session.ID)
	}
}
