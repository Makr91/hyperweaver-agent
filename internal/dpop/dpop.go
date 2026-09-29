package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// Alg is the one proof algorithm the agent accepts.
	Alg = "ES256"
	// ProofWindow is how far a proof's iat may sit from now on either side.
	ProofWindow = 60 * time.Second
	// ReplayWindow is how long a jti stays remembered.
	ReplayWindow = 300 * time.Second
	// MaxJTI caps the jti length a proof may carry.
	MaxJTI = 256

	typProof = "dpop+jwt"
)

var (
	// ErrProof is any refusal of the proof itself.
	ErrProof = errors.New("invalid DPoP proof")
	// ErrBinding is a proof whose key does not match the token's cnf.jkt.
	ErrBinding = errors.New("DPoP key does not match the token binding")
)

type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK *JWK   `json:"jwk"`
}

// JWK is the EC public key a proof carries.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

type claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath"`
}

// Seen remembers proof ids for the replay window, purged on every check.
type Seen struct {
	mu   sync.Mutex
	ids  map[string]time.Time
	hash func(string) string
}

// NewSeen builds the replay store.
func NewSeen() *Seen {
	return &Seen{ids: map[string]time.Time{}, hash: func(jti string) string {
		sum := sha256.Sum256([]byte(jti))
		return string(sum[:])
	}}
}

func (s *Seen) remember(jti string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expires := range s.ids {
		if !expires.After(now) {
			delete(s.ids, key)
		}
	}
	key := s.hash(jti)
	if _, replayed := s.ids[key]; replayed {
		return false
	}
	s.ids[key] = now.Add(ReplayWindow)
	return true
}

// Thumbprint answers the RFC 7638 SHA-256 thumbprint of an EC key, base64url.
func Thumbprint(key *JWK) string {
	canonical := `{"crv":"` + key.Crv + `","kty":"` + key.Kty + `","x":"` + key.X + `","y":"` + key.Y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NormalizeHTU applies RFC 3986 syntax and scheme normalization: lower-case scheme and host, default port dropped, query and fragment dropped.
func NormalizeHTU(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ErrProof
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}

func decodePart(part string) ([]byte, error) {
	if part == "" || strings.ContainsAny(part, "=\n\r ") {
		return nil, ErrProof
	}
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, ErrProof
	}
	return raw, nil
}

func publicKey(key *JWK) (*ecdsa.PublicKey, error) {
	if key == nil || key.Kty != "EC" || key.Crv != "P-256" || key.D != "" {
		return nil, ErrProof
	}
	x, err := decodePart(key.X)
	if err != nil {
		return nil, err
	}
	y, err := decodePart(key.Y)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, ErrProof
	}
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, ErrProof
	}
	return public, nil
}

// Verify checks one proof against the request it covers and the token it binds; boundJKT is the token's cnf.jkt.
func Verify(proof, method, htu, token, boundJKT string, now time.Time, seen *Seen) error {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return ErrProof
	}
	headerRaw, err := decodePart(parts[0])
	if err != nil {
		return err
	}
	var h header
	if uerr := json.Unmarshal(headerRaw, &h); uerr != nil {
		return ErrProof
	}
	if h.Typ != typProof || h.Alg != Alg {
		return ErrProof
	}
	public, err := publicKey(h.JWK)
	if err != nil {
		return err
	}
	signature, err := decodePart(parts[2])
	if err != nil {
		return err
	}
	if len(signature) != 64 {
		return ErrProof
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(public, digest[:], r, s) {
		return ErrProof
	}
	payloadRaw, err := decodePart(parts[1])
	if err != nil {
		return err
	}
	var c claims
	if uerr := json.Unmarshal(payloadRaw, &c); uerr != nil {
		return ErrProof
	}
	if c.JTI == "" || len(c.JTI) > MaxJTI || c.HTM == "" || c.HTU == "" || c.IAT == 0 {
		return ErrProof
	}
	if c.HTM != method {
		return ErrProof
	}
	claimed, err := NormalizeHTU(c.HTU)
	if err != nil {
		return err
	}
	expected, err := NormalizeHTU(htu)
	if err != nil {
		return err
	}
	if claimed != expected {
		return ErrProof
	}
	issued := time.Unix(c.IAT, 0)
	if issued.Before(now.Add(-ProofWindow)) || issued.After(now.Add(ProofWindow)) {
		return ErrProof
	}
	sum := sha256.Sum256([]byte(token))
	if c.ATH != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return ErrProof
	}
	if Thumbprint(h.JWK) != boundJKT {
		return ErrBinding
	}
	if !seen.remember(c.JTI, now) {
		return ErrProof
	}
	return nil
}
