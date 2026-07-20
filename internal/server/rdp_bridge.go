package server

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// The browser-RDP bridge — IronRDP's WebSocket transport, spoken at machine
// scope. The WASM client (iron-remote-desktop-rdp) cannot open raw TCP or
// TLS from a browser, so its wire is Devolutions Gateway's RDCleanPath
// contract (ironrdp-web session.rs: ALWAYS one RDCleanPath request first —
// no raw mode exists): the bridge receives the DER-encoded request PDU over
// the WebSocket, relays the embedded X.224 connection request to the RDP
// server, performs the TLS handshake toward that server ITSELF (the browser
// can't — RDCleanPath terminates TLS at the proxy), answers with the
// RDCleanPath response (X.224 confirm + the server certificate chain the
// client extracts its pinned public key from — the END-TO-END trust anchor
// is that client-side pin, not the bridge's own verification), and then
// pipes raw bytes.
//
// TWO targets (?target=, Mark's 2×2 ruling 2026-07-10):
//   console (default) — the VRDE hypervisor console at 127.0.0.1:<vrde port>,
//     verified against the AGENT CA (the vrde-tls setup mints from it).
//     VirtualBox's VRDE defaults to Standard RDP Security, which no browser
//     path can ride — POST /machines/{name}/vrde-tls is the turnkey fix.
//   guest — a Windows guest's OWN RDP service at its host-reachable IP:3389
//     (resolved by guestRDPAddress: guest agent → Additions → control IP).
//     The guest presents its OWN cert (self-signed or domain-issued), so the
//     bridge does not chain-verify it — the client's pin of the forwarded
//     chain is the trust (Mark's ruling 2026-07-10; Devolutions Gateway's
//     exact model).

// rdCleanPathVersion is the protocol's VERSION_1 (ironrdp-rdcleanpath:
// BASE_VERSION 3389 + 1).
const rdCleanPathVersion = 3390

// rdCleanPathRequest is the client→proxy PDU (DER SEQUENCE, EXPLICIT
// context tags; tag 8 is skipped in the protocol — server_addr is 9).
// Strings are UTF8String inside their context tags (Rust's der::String).
type rdCleanPathRequest struct {
	Version     int64  `asn1:"explicit,tag:0"`
	Destination string `asn1:"explicit,tag:2,optional,utf8"`
	ProxyAuth   string `asn1:"explicit,tag:3,optional,utf8"`
	ServerAuth  string `asn1:"explicit,tag:4,optional,utf8"`
	PCB         string `asn1:"explicit,tag:5,optional,utf8"`
	X224Request []byte `asn1:"explicit,tag:6,optional"`
}

// rdCleanPathResponse is the proxy→client success PDU: the presence of
// server_addr classifies it (the client's into_enum rule).
type rdCleanPathResponse struct {
	Version    int64    `asn1:"explicit,tag:0"`
	X224       []byte   `asn1:"explicit,tag:6"`
	CertChain  [][]byte `asn1:"explicit,tag:7"`
	ServerAddr string   `asn1:"explicit,tag:9,utf8"`
}

// rdCleanPathErrBody is the error SEQUENCE (code 1 = general, 2 =
// negotiation; the optional http/wsa/tls-alert details are never needed
// here).
type rdCleanPathErrBody struct {
	ErrorCode int64 `asn1:"explicit,tag:0"`
}

// rdCleanPathGeneralError is the proxy→client failure PDU.
type rdCleanPathGeneralError struct {
	Version int64              `asn1:"explicit,tag:0"`
	Error   rdCleanPathErrBody `asn1:"explicit,tag:1"`
}

// rdCleanPathNegotiationError carries the server's own X.224 failure confirm
// so the client reports the real negotiation code.
type rdCleanPathNegotiationError struct {
	Version int64              `asn1:"explicit,tag:0"`
	Error   rdCleanPathErrBody `asn1:"explicit,tag:1"`
	X224    []byte             `asn1:"explicit,tag:6"`
}

// derMessageLength answers a DER message's full length once the buffer
// carries the outer SEQUENCE header (0 = need more bytes).
func derMessageLength(buf []byte) (int, error) {
	if len(buf) < 2 {
		return 0, nil
	}
	if buf[0] != 0x30 {
		return 0, errors.New("not a DER SEQUENCE")
	}
	first := buf[1]
	switch {
	case first < 0x80:
		return 2 + int(first), nil
	case first == 0x80:
		return 0, errors.New("indefinite length is not DER")
	default:
		count := int(first & 0x7f)
		if count > 3 {
			return 0, errors.New("unreasonable DER length")
		}
		if len(buf) < 2+count {
			return 0, nil
		}
		length := 0
		for i := 0; i < count; i++ {
			length = length<<8 | int(buf[2+i])
		}
		return 2 + count + length, nil
	}
}

// readCleanPathRequest accumulates WebSocket binary frames until one whole
// DER message arrived (the client may fragment arbitrarily), then decodes it.
func readCleanPathRequest(ctx context.Context, conn *websocket.Conn) (*rdCleanPathRequest, error) {
	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	buf := []byte{}
	for {
		total, err := derMessageLength(buf)
		if err != nil {
			return nil, err
		}
		if total > 64*1024 {
			return nil, errors.New("RDCleanPath request over 64KB")
		}
		if total > 0 && len(buf) >= total {
			request := &rdCleanPathRequest{}
			if _, uerr := asn1.Unmarshal(buf[:total], request); uerr != nil {
				return nil, fmt.Errorf("RDCleanPath request decode: %w", uerr)
			}
			if request.Version != rdCleanPathVersion {
				return nil, fmt.Errorf("RDCleanPath version %d (want %d)", request.Version, rdCleanPathVersion)
			}
			if len(request.X224Request) == 0 {
				return nil, errors.New("RDCleanPath request carries no X.224 connection request")
			}
			return request, nil
		}
		_, data, rerr := conn.Read(readCtx)
		if rerr != nil {
			return nil, rerr
		}
		buf = append(buf, data...)
	}
}

// writeCleanPath marshals one PDU and sends it as a single binary frame.
func writeCleanPath(ctx context.Context, conn *websocket.Conn, pdu any) error {
	raw, err := asn1.Marshal(pdu)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return conn.Write(writeCtx, websocket.MessageBinary, raw)
}

// readTPKT reads exactly one TPKT-framed message (RDP's X.224 wire: version
// 3, big-endian total length including the 4-byte header).
func readTPKT(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[0] != 3 {
		return nil, errors.New("not a TPKT header")
	}
	total := int(binary.BigEndian.Uint16(header[2:4]))
	if total < 5 || total > 4096 {
		return nil, errors.New("unreasonable TPKT length")
	}
	rest := make([]byte, total-4)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return nil, err
	}
	return append(header, rest...), nil
}

// x224ConfirmOutcome reads the RDP negotiation payload out of a Connection
// Confirm: TPKT(4) + LI(1) + CC(1) + dst(2) + src(2) + class(1), then the
// optional RDP_NEG structure {type(1) flags(1) length(2 LE) value(4 LE)}.
// hasPayload=false means the server answered pre-negotiation RDP (Standard
// Security only — no TLS possible on this connection).
func x224ConfirmOutcome(confirm []byte) (selected uint32, failure, hasPayload bool) {
	if len(confirm) < 19 {
		return 0, false, false
	}
	switch confirm[11] {
	case 0x02: // TYPE_RDP_NEG_RSP
		return binary.LittleEndian.Uint32(confirm[15:19]), false, true
	case 0x03: // TYPE_RDP_NEG_FAILURE
		return 0, true, true
	}
	return 0, false, false
}

// handleRDPBridge serves GET /machines/{machineName}/rdp-bridge (WebSocket,
// ?ticket= auth like every upgrade): the IronRDP web client's transport.
// The RDCleanPath destination field is advisory here — the ticket already
// authorized THIS machine's bridge and both targets resolve server-side
// (VRDE port from the live view; guest IP via guestRDPAddress), so the
// bridge never dials a client-chosen address.
//
//	@Summary		Browser-RDP bridge (WebSocket)
//	@Description	WEBSOCKET upgrade — authenticate with ?ticket= (GET /ws-ticket). The IronRDP web client's transport (iron-remote-desktop-rdp, proxyAddress = this URL): the client cannot open TCP or TLS from a browser, so its wire is the RDCleanPath contract — the bridge reads the client's DER-encoded RDCleanPath request (first binary frames), relays the embedded X.224 connection request to the chosen RDP server, performs the TLS handshake toward that server ITSELF, answers the RDCleanPath response (X.224 confirm + the server certificate chain the client pins), and then pipes raw bytes both ways. TWO targets via ?target= (GET /machines/{name}/rdp's same vocabulary): console (default) = the machine's VRDE port at 127.0.0.1, TLS VERIFIED against the AGENT CA; guest = a Windows guest's OWN RDP service at its host-reachable IP:3389 (resolved like the rdp launcher: guest agent → Guest Additions → control IP) — the guest presents its OWN certificate (self-signed or domain-issued), so the bridge forwards the chain UNVERIFIED and the client's pin of it is the trust anchor (Devolutions Gateway's model; Mark's ruling 2026-07-11). The PDU's destination field is advisory: both targets resolve server-side, never from the client. SELF-HEALING (console target, Mark's zero-click ruling 2026-07-11): a VRDE server answering without TLS gets the whole VRDE TLS setup applied LIVE — certificate minted from the agent CA, Security properties set via controlvm vrdeproperty (the VRDP server reads them per connection; no power cycle) — and the relay retries once, so the first browser connect to an unconfigured machine (vagrant-up, GUI-created, anything) just works. Persistent negotiation failures ride through as RDCleanPath errors (guest target on Standard security = the guest's own RDP settings disable TLS — unhealable from the host).
//	@Tags			Console
//	@Param			machineName	path	string	true	"Machine name"
//	@Param			ticket	query	string	true	"WebSocket upgrade ticket (GET /ws-ticket)"
//	@Param			target	query	string	false	"console = the VRDE hypervisor console (agent-CA-verified TLS); guest = the guest's own RDP service at its host-reachable IP (chain forwarded unverified — the client pin is the trust)"	Enums(console, guest)	default(console)
//	@Success		101	"Switching Protocols — RDCleanPath handshake, then raw RDP flows"
//	@Failure		400	"Machine not running, unknown target, no active VRDE console (console target), or no host-reachable guest IP (guest target)"
//	@Failure		401	"Missing or invalid ticket"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed, or the agent CA is unavailable (console target)"
//	@Router			/machines/{machineName}/rdp-bridge [get]
func (s *Server) handleRDPBridge(w http.ResponseWriter, r *http.Request) {
	if !s.requireTicket(w, r) {
		return
	}
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "console"
	}
	if target != "console" && target != "guest" {
		taskError(w, http.StatusBadRequest, "Unknown bridge target (console | guest)")
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if err != nil {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if machines.MapVBoxState(info.State) != machines.StatusRunning {
		taskError(w, http.StatusBadRequest, "Machine is not running")
		return
	}

	var address string
	var tlsCfg *tls.Config
	if target == "guest" {
		ip := s.guestRDPAddress(r.Context(), exe, machine, machines.ParseConfiguration(machine))
		if ip == "" {
			taskError(w, http.StatusBadRequest,
				"No host-reachable guest IP is known (guest agent silent, Guest Additions report none, no control IP in networks[])")
			return
		}
		address = net.JoinHostPort(ip, "3389")
		// The guest presents its OWN certificate (self-signed or
		// domain-issued — nothing the agent CA ever minted), so the bridge
		// forwards the chain unverified and the client's pin of it is the
		// trust anchor (Mark's ruling 2026-07-11; Devolutions Gateway's
		// exact model).
		tlsCfg = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // guest RDP certs are foreign by design; trust = client-side pin of the forwarded chain
			MinVersion:         tls.VersionTLS12,
		}
	} else {
		enabled, port := vrdePort(info)
		if !enabled || port <= 0 {
			taskError(w, http.StatusBadRequest,
				"Machine has no active VRDE console — POST /machines/{name}/vrde-tls sets up the browser-RDP path")
			return
		}
		pool, perr := s.agentCAPool()
		if perr != nil {
			taskError(w, http.StatusServiceUnavailable,
				"Agent CA unavailable — POST /machines/{name}/vrde-tls generates it with the machine's VRDE certificate")
			return
		}
		address = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		tlsCfg = &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		}
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		slog.Warn("rdp bridge accept failed", "machine", machine.Name, "error", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")
	conn.SetReadLimit(1 << 20)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	request, err := readCleanPathRequest(ctx, conn)
	if err != nil {
		slog.Warn("rdp bridge handshake failed", "machine", machine.Name, "error", err)
		return
	}

	// X.224 relay with ONE self-heal retry (console target): a VRDE server
	// answering "no TLS" (negotiation failure or a Standard-security confirm)
	// gets the VRDE TLS setup applied LIVE — controlvm vrdeproperty, no power
	// cycle (Mark's zero-click ruling 2026-07-11) — and the relay retries.
	// The first browser connect to an unconfigured machine just works.
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var backend net.Conn
	var confirm []byte
	var selected uint32
	healed := false
	for {
		var derr error
		backend, derr = dialer.DialContext(ctx, "tcp", address)
		if derr != nil {
			slog.Warn("rdp bridge dial failed", "machine", machine.Name, "target", target, "address", address, "error", derr)
			_ = writeCleanPath(ctx, conn, rdCleanPathGeneralError{
				Version: rdCleanPathVersion, Error: rdCleanPathErrBody{ErrorCode: 1},
			})
			return
		}
		if _, werr := backend.Write(request.X224Request); werr != nil {
			_ = backend.Close()
			_ = writeCleanPath(ctx, conn, rdCleanPathGeneralError{
				Version: rdCleanPathVersion, Error: rdCleanPathErrBody{ErrorCode: 1},
			})
			return
		}
		var rerr error
		confirm, rerr = readTPKT(backend)
		if rerr != nil {
			_ = backend.Close()
			slog.Warn("rdp bridge x224 read failed", "machine", machine.Name, "error", rerr)
			_ = writeCleanPath(ctx, conn, rdCleanPathGeneralError{
				Version: rdCleanPathVersion, Error: rdCleanPathErrBody{ErrorCode: 1},
			})
			return
		}
		var failed, hasPayload bool
		selected, failed, hasPayload = x224ConfirmOutcome(confirm)
		if !failed && hasPayload && selected != 0 {
			break // TLS negotiated — proceed to the handshake.
		}
		_ = backend.Close()

		if target == "console" && !healed {
			healed = true
			herr := s.healVRDETLS(ctx, exe, machine)
			if herr == nil {
				slog.Info("rdp bridge: VRDE answered without TLS — TLS setup applied live, retrying",
					"machine", machine.Name)
				// The property change restarts the VRDE listener; give it a
				// moment to rebind before the retry dial.
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				continue
			}
			slog.Warn("rdp bridge: VRDE TLS self-heal failed", "machine", machine.Name, "error", herr)
		}
		if failed {
			// The server's own failure confirm rides through — the client
			// decodes the real negotiation code out of it.
			_ = writeCleanPath(ctx, conn, rdCleanPathNegotiationError{
				Version: rdCleanPathVersion, Error: rdCleanPathErrBody{ErrorCode: 2}, X224: confirm,
			})
			return
		}
		// Standard RDP Security and unhealable (guest target: the guest's own
		// RDP settings disable TLS) — nothing a browser can ride.
		slog.Warn("rdp bridge: server answered Standard RDP Security",
			"machine", machine.Name, "target", target)
		_ = writeCleanPath(ctx, conn, rdCleanPathGeneralError{
			Version: rdCleanPathVersion, Error: rdCleanPathErrBody{ErrorCode: 1},
		})
		return
	}
	defer func() {
		_ = backend.Close()
	}()

	tlsConn := tls.Client(backend, tlsCfg)
	handshakeCtx, handshakeDone := context.WithTimeout(ctx, 10*time.Second)
	err = tlsConn.HandshakeContext(handshakeCtx)
	handshakeDone()
	if err != nil {
		slog.Warn("rdp bridge TLS handshake failed (console target: certificate not chained to the agent CA? run POST /machines/{name}/vrde-tls)",
			"machine", machine.Name, "target", target, "error", err)
		_ = writeCleanPath(ctx, conn, rdCleanPathGeneralError{
			Version: rdCleanPathVersion, Error: rdCleanPathErrBody{ErrorCode: 1},
		})
		return
	}
	chain := [][]byte{}
	for _, cert := range tlsConn.ConnectionState().PeerCertificates {
		chain = append(chain, cert.Raw)
	}
	if werr := writeCleanPath(ctx, conn, rdCleanPathResponse{
		Version:    rdCleanPathVersion,
		X224:       confirm,
		CertChain:  chain,
		ServerAddr: address,
	}); werr != nil {
		return
	}

	// Raw pipe from here (the websockify pattern): WS binary ↔ the TLS stream.
	go func() {
		defer cancel()
		for {
			_, data, rerr := conn.Read(ctx)
			if rerr != nil {
				return
			}
			if _, werr := tlsConn.Write(data); werr != nil {
				return
			}
		}
	}()
	buffer := make([]byte, 32*1024)
	for {
		length, rerr := tlsConn.Read(buffer)
		if length > 0 {
			writeCtx, done := context.WithTimeout(ctx, 30*time.Second)
			werr := conn.Write(writeCtx, websocket.MessageBinary, buffer[:length])
			done()
			if werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
