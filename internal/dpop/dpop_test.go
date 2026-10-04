package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"
)

func pad32(value *big.Int) []byte {
	out := make([]byte, 32)
	value.FillBytes(out)
	return out
}

func encode(value any) string {
	raw, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(raw)
}

type signer struct {
	key *ecdsa.PrivateKey
	jwk *JWK
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uncompressed, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk := &JWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(uncompressed[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(uncompressed[33:65]),
	}
	return &signer{key: key, jwk: jwk}
}

func (s *signer) proof(t *testing.T, head, body map[string]any) string {
	t.Helper()
	if head == nil {
		head = map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": s.jwk}
	}
	input := encode(head) + "." + encode(body)
	digest := sha256.Sum256([]byte(input))
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(append(pad32(r), pad32(sig)...))
}

func ath(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestThumbprintMatchesRFC7638Shape(t *testing.T) {
	key := &JWK{Kty: "EC", Crv: "P-256", X: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", Y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}
	if got := Thumbprint(key); got != "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" {
		t.Fatalf("thumbprint of the RFC 9449 example key is %s", got)
	}
}

func TestNormalizeHTU(t *testing.T) {
	got, err := NormalizeHTU("HTTPS://Auth.Example.com:443/api/x?q=1#f")
	if err != nil || got != "https://auth.example.com/api/x" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = NormalizeHTU("https://127.0.0.1:9421/api/machines")
	if err != nil || got != "https://127.0.0.1:9421/api/machines" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestVerifyAcceptsAGoodProof(t *testing.T) {
	s := newSigner(t)
	now := time.Now()
	token := "access.token.value"
	proof := s.proof(t, nil, map[string]any{
		"jti": "abc123", "htm": "GET", "htu": "https://127.0.0.1:9421/api/machines", "iat": now.Unix(), "ath": ath(token),
	})
	seen := NewSeen()
	if err := Verify(proof, "GET", "https://127.0.0.1:9421/api/machines?x=1", token, Thumbprint(s.jwk), now, seen); err != nil {
		t.Fatal(err)
	}
	if err := Verify(proof, "GET", "https://127.0.0.1:9421/api/machines", token, Thumbprint(s.jwk), now, seen); !errors.Is(err, ErrProof) {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestVerifyRefusals(t *testing.T) {
	s := newSigner(t)
	now := time.Now()
	token := "tok"
	good := map[string]any{"jti": "j", "htm": "POST", "htu": "https://a/b", "iat": now.Unix(), "ath": ath(token)}
	cases := []struct {
		name   string
		head   map[string]any
		body   map[string]any
		method string
		htu    string
		jkt    string
		want   error
	}{
		{"wrong method", nil, good, "GET", "https://a/b", Thumbprint(s.jwk), ErrProof},
		{"wrong htu", nil, good, "POST", "https://a/c", Thumbprint(s.jwk), ErrProof},
		{"wrong binding", nil, good, "POST", "https://a/b", "other", ErrBinding},
		{"stale iat", nil, map[string]any{"jti": "j2", "htm": "POST", "htu": "https://a/b", "iat": now.Add(-2 * time.Minute).Unix(), "ath": ath(token)}, "POST", "https://a/b", Thumbprint(s.jwk), ErrProof},
		{"wrong ath", nil, map[string]any{"jti": "j3", "htm": "POST", "htu": "https://a/b", "iat": now.Unix(), "ath": ath("x")}, "POST", "https://a/b", Thumbprint(s.jwk), ErrProof},
		{"wrong typ", map[string]any{"typ": "JWT", "alg": "ES256", "jwk": s.jwk}, good, "POST", "https://a/b", Thumbprint(s.jwk), ErrProof},
		{"private key", map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": &JWK{Kty: "EC", Crv: "P-256", X: s.jwk.X, Y: s.jwk.Y, D: "secret"}}, good, "POST", "https://a/b", Thumbprint(s.jwk), ErrProof},
	}
	for _, tc := range cases {
		err := Verify(s.proof(t, tc.head, tc.body), tc.method, tc.htu, token, tc.jkt, now, NewSeen())
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}
