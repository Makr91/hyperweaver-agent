package server

import (
	"bytes"
	"sync"
)

const terminalBufferLimit = 256 << 10

// terminalLink carries one shell's output to the socket attached now and keeps the last terminalBufferLimit bytes for the next socket.
type terminalLink struct {
	mu     sync.Mutex
	buffer []byte
	send   func(string)
	serial uint64
}

func (l *terminalLink) output(text string) {
	l.mu.Lock()
	l.buffer = append(l.buffer, text...)
	if len(l.buffer) > terminalBufferLimit {
		l.buffer = l.buffer[len(l.buffer)-terminalBufferLimit:]
		if cut := bytes.IndexByte(l.buffer, '\n'); cut >= 0 && cut < len(l.buffer)-1 {
			l.buffer = l.buffer[cut+1:]
		}
	}
	send := l.send
	l.mu.Unlock()
	if send != nil {
		send(text)
	}
}

// attach replays the kept output to send, makes it the live writer in place of any earlier one and answers the handle detach takes.
func (l *terminalLink) attach(send func(string)) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buffer) > 0 {
		send(string(l.buffer))
	}
	l.send = send
	l.serial++
	return l.serial
}

func (l *terminalLink) detach(handle uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.serial == handle {
		l.send = nil
	}
}

func (l *terminalLink) attached() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.send != nil
}
