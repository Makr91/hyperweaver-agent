// Package qga speaks the QEMU Guest Agent protocol over VirtualBox's UART
// pipe — the credential-less guest channel (Mark's go 2026-07-10, spike-
// proven the same day on Debian 12 and Windows Server 2022 guests): the
// guest runs qemu-ga on COM2 (isa-serial), VirtualBox exposes the UART as a
// named pipe (Windows hosts) or local domain socket (elsewhere), and this
// package is the ONE client that channel gets — the transport takes exactly
// one, a stray PuTTY kills it (spike lesson).
//
// Wire: newline-terminated JSON both ways. Every exchange opens the pipe
// fresh, resynchronizes with guest-sync-delimited (the 0xFF sentinel flushes
// any stale partial line a previous client left), runs ONE command, and
// closes — the channel is free between calls.
package qga

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ErrNoReply marks a command that was delivered but never answered — the
// expected outcome of guest-shutdown (the guest can die before replying).
var ErrNoReply = errors.New("guest agent accepted the command but sent no reply")

// Per-channel serialization (the UI AI's runtime find 2026-07-11): the pipe
// takes ONE client, so two concurrent commands — a browser guest/* call
// racing an RDP-target lookup or the discovery sweep — collide on the open
// and randomly kill each other's answers. Every Do waits its turn per pipe;
// the map is bounded by machine count.
var (
	channelsMu sync.Mutex
	channels   = map[string]*sync.Mutex{}
)

// channelLock answers the pipe's own mutex, minting it on first use.
func channelLock(pipe string) *sync.Mutex {
	channelsMu.Lock()
	defer channelsMu.Unlock()
	lock, ok := channels[pipe]
	if !ok {
		lock = &sync.Mutex{}
		channels[pipe] = lock
	}
	return lock
}

// PipePath is the machine's QGA channel address: a named pipe on Windows
// hosts, a qga.sock under the machine's working directory elsewhere. The
// create wiring and every caller derive it from the same inputs so they can
// never disagree.
func PipePath(workdir, machineName string) string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\hyperweaver-qga-` + sanitizeName(machineName)
	}
	return filepath.Join(workdir, "qga.sock")
}

// sanitizeName maps a free-form machine name (design D-G) onto the pipe-name
// alphabet.
func sanitizeName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}

// open connects to the channel (the VM owns the server end — it exists only
// while the machine runs).
func open(ctx context.Context, pipe string) (io.ReadWriteCloser, error) {
	if runtime.GOOS == "windows" {
		file, err := os.OpenFile(filepath.Clean(pipe), os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("open guest-agent pipe: %w", err)
		}
		return file, nil
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", pipe)
	if err != nil {
		return nil, fmt.Errorf("open guest-agent socket: %w", err)
	}
	return conn, nil
}

// Do runs one guest-agent command: open, guest-sync-delimited, execute, read
// the reply, close. The pipe has no read deadlines, so the context is the
// timeout — expiry closes the channel out from under the blocked read.
// Access is serialized per channel: concurrent callers queue, never collide.
func Do(ctx context.Context, pipe, execute string, arguments any) (json.RawMessage, error) {
	lock := channelLock(pipe)
	lock.Lock()
	defer lock.Unlock()

	conn, err := open(ctx, pipe)
	if err != nil {
		return nil, err
	}
	type outcome struct {
		raw json.RawMessage
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		raw, xerr := exchange(conn, execute, arguments)
		done <- outcome{raw, xerr}
	}()
	select {
	case result := <-done:
		_ = conn.Close()
		return result.raw, result.err
	case <-ctx.Done():
		_ = conn.Close()
		result := <-done
		if result.err != nil && !errors.Is(result.err, ErrNoReply) {
			return nil, fmt.Errorf("guest agent did not answer: %w", ctx.Err())
		}
		return result.raw, result.err
	}
}

// exchange is the sequential wire conversation on an open channel.
func exchange(conn io.ReadWriteCloser, execute string, arguments any) (json.RawMessage, error) {
	reader := bufio.NewReader(conn)

	// Resync: 0xFF flushes the guest's parser, guest-sync-delimited echoes the
	// id after its own 0xFF — everything before the sentinel is stale noise.
	syncID := time.Now().UnixNano() & 0x7fffffff
	syncReq, err := json.Marshal(map[string]any{
		"execute":   "guest-sync-delimited",
		"arguments": map[string]any{"id": syncID},
	})
	if err != nil {
		return nil, err
	}
	if _, werr := conn.Write(append(append([]byte{0xff}, syncReq...), '\n')); werr != nil {
		return nil, fmt.Errorf("guest-sync write: %w", werr)
	}
	for {
		b, rerr := reader.ReadByte()
		if rerr != nil {
			return nil, fmt.Errorf("guest-sync read: %w", rerr)
		}
		if b == 0xff {
			break
		}
	}
	var syncAnswer struct {
		Return int64 `json:"return"`
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("guest-sync read: %w", err)
	}
	if uerr := json.Unmarshal([]byte(line), &syncAnswer); uerr != nil || syncAnswer.Return != syncID {
		return nil, fmt.Errorf("guest-sync answered %q (want id %d)", strings.TrimSpace(line), syncID)
	}

	request := map[string]any{"execute": execute}
	if arguments != nil {
		request["arguments"] = arguments
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if _, werr := conn.Write(append(raw, '\n')); werr != nil {
		return nil, fmt.Errorf("command write: %w", werr)
	}

	line, err = reader.ReadString('\n')
	if err != nil {
		// Delivered but unanswered — guest-shutdown's normal exit.
		return nil, ErrNoReply
	}
	var response struct {
		Return json.RawMessage `json:"return"`
		Error  *struct {
			Class string `json:"class"`
			Desc  string `json:"desc"`
		} `json:"error"`
	}
	if uerr := json.Unmarshal([]byte(line), &response); uerr != nil {
		return nil, fmt.Errorf("parse guest answer %q: %w", strings.TrimSpace(line), uerr)
	}
	if response.Error != nil {
		return nil, fmt.Errorf("guest agent error (%s): %s", response.Error.Class, response.Error.Desc)
	}
	return response.Return, nil
}

// networkInterface is guest-network-get-interfaces' per-interface shape.
type networkInterface struct {
	Name        string `json:"name"`
	Hardware    string `json:"hardware-address"`
	IPAddresses []struct {
		Type    string `json:"ip-address-type"`
		Address string `json:"ip-address"`
		Prefix  int    `json:"prefix"`
	} `json:"ip-addresses"`
}

// GuestIPv4s answers the guest's host-reachable IPv4 addresses — the
// live-truth source of the RDP/SSH target ladders and the discovery sweep's
// stored guest_info: loopback and the provisioning NAT's 10.0.2.x are
// excluded, exactly like the Guest Additions path. A nil error with an empty
// list means the agent ANSWERED but reported nothing host-reachable — that
// distinction (responding vs silent) is the stored gate's honesty.
func GuestIPv4s(ctx context.Context, pipe string) ([]string, error) {
	raw, err := Do(ctx, pipe, "guest-network-get-interfaces", nil)
	if err != nil {
		return nil, err
	}
	var interfaces []networkInterface
	if uerr := json.Unmarshal(raw, &interfaces); uerr != nil {
		return nil, fmt.Errorf("parse guest interfaces: %w", uerr)
	}
	ips := []string{}
	for _, iface := range interfaces {
		for _, addr := range iface.IPAddresses {
			if addr.Type != "ipv4" || addr.Address == "" {
				continue
			}
			if strings.HasPrefix(addr.Address, "127.") ||
				strings.HasPrefix(addr.Address, "10.0.2.") ||
				addr.Address == "0.0.0.0" {
				continue
			}
			ips = append(ips, addr.Address)
		}
	}
	return ips, nil
}
