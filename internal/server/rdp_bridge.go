package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/sslcert"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
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

// agentCAPool loads the agent CA — the VRDE certificate's trust root (the
// vrde-tls setup mints from it; BYO material must chain to it too).
func (s *Server) agentCAPool() (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(s.cfg.SSLCACertPath()))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("agent CA certificate is not PEM")
	}
	return pool, nil
}

// vrdeCertDir is where a machine's minted VRDE TLS material lives: beside
// the agent's own ssl tree, surviving as long as the configuration does
// (the create executor mints into the same root).
func (s *Server) vrdeCertDir(machineName string) string {
	return filepath.Join(s.cfg.VRDECertRoot(), machineName)
}

// vrdeTLSProperties mints (or reuses) the machine's VRDE TLS material and
// answers the four Security properties in name=value form — the ONE list the
// live self-heal, the setup endpoint, and the queued modify all speak.
func (s *Server) vrdeTLSProperties(machineName string) (certPath string, properties []string, err error) {
	certPath, keyPath, caPath, err := sslcert.EnsureVRDECertificate(
		s.cfg.SSLCACertPath(), s.cfg.SSLCAKeyPath(),
		s.vrdeCertDir(machineName), machineName)
	if err != nil {
		return "", nil, err
	}
	return certPath, []string{
		"Security/Method=Negotiate",
		"Security/ServerCertificate=" + certPath,
		"Security/ServerPrivateKey=" + keyPath,
		"Security/CACertificate=" + caPath,
	}, nil
}

// healVRDETLS applies the VRDE TLS setup to a RUNNING machine LIVE:
// controlvm vrdeproperty — the VRDP server queries Security/* per client
// connection (VirtualBox-source-verified + runtime-proven on Mark's 7.2,
// 2026-07-11), so the properties take effect for the NEXT connect with no
// power cycle, and they persist into the machine settings like modifyvm's.
// Applying restarts the VRDE listener (existing RDP sessions drop; the VM
// is untouched).
func (s *Server) healVRDETLS(ctx context.Context, vboxExe string, machine *machines.Machine) error {
	_, properties, err := s.vrdeTLSProperties(machine.Name)
	if err != nil {
		return err
	}
	for _, property := range properties {
		if perr := vbox.ControlVMArgs(ctx, vboxExe, machine.VBoxTarget(), "vrdeproperty", property); perr != nil {
			return perr
		}
	}
	return nil
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

// handleVRDETLSSetup serves POST /machines/{machineName}/vrde-tls — turnkey
// Enhanced-security VRDE (the browser-RDP path's floor): mints the machine's
// VRDE certificate from the agent CA and pushes the VRDE TLS properties —
// plus VRDE itself when off — RUNNING machines get the security properties
// LIVE (controlvm vrdeproperty; no power cycle) with the modifyvm-bound
// extras accrued; powered-off machines get everything as a queued modify.
// Near-obsolete since the bridge self-heals and create mints from birth —
// kept as the explicit prep path. Method stays Negotiate so mstsc and other
// native clients keep connecting however they like; the bridge always asks
// for TLS and gets it.
//
//	@Summary		Set up VRDE TLS (Enhanced RDP Security)
//	@Description	Minimum role: operator. Explicit VRDE TLS prep — NEAR-OBSOLETE since machine creation mints the TLS material from birth and the rdp-bridge SELF-HEALS unconfigured machines live at first connect (Mark's zero-click ruling 2026-07-11); kept as the manual prep path. Mints the machine's VRDE certificate signed by the AGENT CA (loopback SANs; files under <config dir>/ssl/vrde/<machine>/ — reused, never regenerated) and applies Security/Method=Negotiate + the certificate/key/CA paths. RUNNING machines: applied LIVE via controlvm vrdeproperty (status applied_live, requires_restart false — the VRDP server reads Security/* per connection; the VRDE listener restarts, dropping active RDP sessions, VM untouched), with the modifyvm-bound console extras (multi-con, reuse-con, usbtablet, usb keyboard, xHCI, clipboard) accrued for the next power cycle (pending_changes in the answer). POWERED-OFF machines: everything as one queued machine_modify. Negotiate keeps native clients (mstsc) connecting however they like; the bridge always asks for TLS and gets it.
//	@Tags			Console
//	@Produce		json
//	@Param			machineName	path	string	true	"Machine name"
//	@Success		200	{object}	map[string]interface{}	"TLS applied live (running), setup queued (powered off), or accrued (live apply failed)"
//	@Failure		404	"Machine not found, or no VM exists behind it yet"
//	@Failure		503	"VirtualBox is not installed"
//	@Router			/machines/{machineName}/vrde-tls [post]
func (s *Server) handleVRDETLSSetup(w http.ResponseWriter, r *http.Request) {
	machine := s.findMachine(w, r)
	if machine == nil {
		return
	}
	exe := machines.VBoxManagePath(r.Context())
	if exe == "" {
		taskError(w, http.StatusServiceUnavailable, "VirtualBox is not installed")
		return
	}
	info, err := vbox.ShowVMInfo(r.Context(), exe, machine.VBoxTarget())
	if errors.Is(err, vbox.ErrNotFound) {
		taskError(w, http.StatusNotFound, "No VM exists behind this machine yet")
		return
	}
	if err != nil {
		slog.Error("vrde-tls probe", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to read machine state")
		return
	}

	certPath, securityProperties, err := s.vrdeTLSProperties(machine.Name)
	if err != nil {
		slog.Error("vrde certificate generation", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to generate the VRDE certificate: "+err.Error())
		return
	}

	securityDirectives := make([]any, 0, len(securityProperties))
	for _, property := range securityProperties {
		securityDirectives = append(securityDirectives,
			map[string]any{"directive": "vrde-property", "value": property})
	}
	extraDirectives := []any{
		// Parallel console sessions: without this a browser reconnect (the old
		// TCP still lingering) or a second client answers "AUTH: Multiple
		// connections are not enabled" (Mark's ask 2026-07-10); reuse-con
		// keeps the guest session across reconnects (the bridge opens a fresh
		// WS per console open — Mark's directive after live testing).
		map[string]any{"directive": "vrde-multi-con", "value": "on"},
		map[string]any{"directive": "vrde-reuse-con", "value": "on"},
		// The browser-console input/clipboard defaults (Mark's directive
		// 2026-07-10): absolute pointer, USB keyboard, xHCI, clipboard both
		// ways — the machine was EXPLICITLY being prepped for browser
		// consoles, so the input experience comes along.
		map[string]any{"directive": "mouse", "value": "usbtablet"},
		map[string]any{"directive": "keyboard", "value": "usb"},
		map[string]any{"directive": "usb-xhci", "value": "on"},
		map[string]any{"directive": "clipboard-mode", "value": "bidirectional"},
		map[string]any{"directive": "clipboard-file-transfers", "value": "enabled"},
	}
	doc := map[string]any{"vbox": map[string]any{"directives": append(append([]any{}, securityDirectives...), extraDirectives...)}}
	if info.Raw["vrde"] != "on" {
		doc["vnc"] = "on"
	}

	// RUNNING machines get the security properties applied LIVE (controlvm
	// vrdeproperty — Mark's zero-click ruling 2026-07-11): the next connect
	// negotiates TLS, no power cycle. Only the modifyvm-bound extras (input,
	// clipboard, multi-con) still accrue. A live-apply failure falls back to
	// accruing the whole set — today's behavior, honestly reported.
	if machines.MapVBoxState(info.State) == machines.StatusRunning {
		exe := machines.VBoxManagePath(r.Context())
		applyErr := error(nil)
		for _, property := range securityProperties {
			if perr := vbox.ControlVMArgs(r.Context(), exe, machine.VBoxTarget(), "vrdeproperty", property); perr != nil {
				applyErr = perr
				break
			}
		}
		if applyErr == nil {
			extrasDoc := map[string]any{"vbox": map[string]any{"directives": extraDirectives}}
			if info.Raw["vrde"] != "on" {
				extrasDoc["vnc"] = "on"
			}
			merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, extrasDoc)
			if merr != nil {
				slog.Error("accrue vrde-tls extras", "machine", machine.Name, "error", merr)
				taskError(w, http.StatusInternalServerError, "TLS applied live, but storing the console extras failed")
				return
			}
			slog.Info("vrde tls applied live", "machine", machine.Name, "by", auth.FromContext(r.Context()).Name)
			writeJSON(w, map[string]any{
				"success":          true,
				"machine_name":     machine.Name,
				"operation":        machines.OpModify,
				"status":           "applied_live",
				"requires_restart": false,
				"pending_changes":  merged,
				"certificate":      certPath,
				"message":          "VRDE TLS applied LIVE — the next connect negotiates Enhanced security. Console input/clipboard extras accrued for the next power cycle.",
			})
			return
		}
		slog.Warn("vrde tls live apply failed — accruing instead", "machine", machine.Name, "error", applyErr)
	}

	switch machines.MapVBoxState(info.State) {
	case machines.StatusStopped, machines.StatusAborted:
		metadata, merr := json.Marshal(doc)
		if merr != nil {
			taskError(w, http.StatusInternalServerError, "Failed to queue the VRDE TLS setup")
			return
		}
		metadataStr := string(metadata)
		task, terr := s.tasks.Store().Create(r.Context(), &tasks.NewTask{
			MachineName: machine.Name,
			Operation:   machines.OpModify,
			Priority:    tasks.PriorityMedium,
			CreatedBy:   auth.FromContext(r.Context()).Name,
			Metadata:    &metadataStr,
		})
		if terr != nil {
			slog.Error("queue vrde-tls task", "machine", machine.Name, "error", terr)
			taskError(w, http.StatusInternalServerError, "Failed to queue the VRDE TLS setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"task_id":          task.ID,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           tasks.StatusPending,
			"requires_restart": true,
			"certificate":      certPath,
			"message":          "VRDE TLS setup queued — the certificate is minted and the VRDE properties apply now (machine is powered off).",
		})
	default:
		merged, merr := s.machines.MergePendingChanges(r.Context(), machine.Name, doc)
		if merr != nil {
			slog.Error("accrue vrde-tls changes", "machine", machine.Name, "error", merr)
			taskError(w, http.StatusInternalServerError, "Failed to store the VRDE TLS setup")
			return
		}
		writeJSON(w, map[string]any{
			"success":          true,
			"machine_name":     machine.Name,
			"operation":        machines.OpModify,
			"status":           "pending_power_cycle",
			"requires_restart": true,
			"pending_changes":  merged,
			"certificate":      certPath,
			"message":          "VRDE TLS setup accrued — the certificate is minted; the VRDE properties apply at the next agent-driven power cycle (stop, start, or restart).",
		})
	}
}
