package assets

import (
	"crypto/md5"  // #nosec G501 -- verifies a registry's published MD5 against the stream, never a security decision
	"crypto/sha1" // #nosec G505 -- verifies a registry's published SHA-1 against the stream, never a security decision
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"strings"
)

// The checksum algorithms a caller may name beside its checksum; sha256 stays the artifact's own key.
const (
	AlgorithmMD5    = "md5"
	AlgorithmSHA1   = "sha1"
	AlgorithmSHA256 = "sha256"
	AlgorithmSHA384 = "sha384"
	AlgorithmSHA512 = "sha512"
)

var checksumLengths = map[string]int{
	AlgorithmMD5:    32,
	AlgorithmSHA1:   40,
	AlgorithmSHA256: 64,
	AlgorithmSHA384: 96,
	AlgorithmSHA512: 128,
}

// ValidAlgorithm reports whether s names a checksum algorithm the agent verifies with.
func ValidAlgorithm(s string) bool {
	_, ok := checksumLengths[s]
	return ok
}

// NormalizeAlgorithm lowercases a checksum algorithm name and answers sha256 for an empty one, so a registry's SHA256 and a caller's sha256 read the same.
func NormalizeAlgorithm(s string) string {
	if s == "" {
		return AlgorithmSHA256
	}
	return strings.ToLower(s)
}

// ValidateChecksum checks a hex checksum against its algorithm's digest length.
func ValidateChecksum(checksum, algorithm string) error {
	if checksum == "" {
		return nil
	}
	length, ok := checksumLengths[algorithm]
	if !ok {
		return errors.New("checksum_algorithm must be one of md5, sha1, sha256, sha384, sha512")
	}
	if len(checksum) != length {
		return errors.New("checksum must be a " + algorithm + " digest of " + hexLength(length) + " hex characters")
	}
	for _, r := range checksum {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return errors.New("checksum must be hex")
		}
	}
	return nil
}

func hexLength(n int) string {
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// Hashes computes the artifact's sha256 and, when another algorithm is named, that digest too, from one pass over the stream.
type Hashes struct {
	sha256    hash.Hash
	other     hash.Hash
	algorithm string
}

// NewHashes prepares the hashers for one stream; algorithm is the caller's, sha256 or empty adding nothing beside the artifact's own.
func NewHashes(algorithm string) *Hashes {
	h := &Hashes{sha256: sha256.New(), algorithm: NormalizeAlgorithm(algorithm)}
	switch h.algorithm {
	case AlgorithmMD5:
		h.other = md5.New() // #nosec G401 -- registry-published digest, verification only
	case AlgorithmSHA1:
		h.other = sha1.New() // #nosec G401 -- registry-published digest, verification only
	case AlgorithmSHA384:
		h.other = sha512.New384()
	case AlgorithmSHA512:
		h.other = sha512.New()
	}
	return h
}

// Writer answers the writer the stream is teed into.
func (h *Hashes) Writer() io.Writer {
	if h.other == nil {
		return h.sha256
	}
	return io.MultiWriter(h.sha256, h.other)
}

// SHA256 answers the artifact's own digest.
func (h *Hashes) SHA256() string {
	return hex.EncodeToString(h.sha256.Sum(nil))
}

// Given answers the digest under the caller's algorithm, the sha256 when that is the algorithm.
func (h *Hashes) Given() string {
	if h.other == nil {
		return h.SHA256()
	}
	return hex.EncodeToString(h.other.Sum(nil))
}

// Matches reports whether the stream's digest under the caller's algorithm equals checksum.
func (h *Hashes) Matches(checksum string) bool {
	return strings.EqualFold(h.Given(), checksum)
}

// HashFileWith computes a file's sha256 and its digest under algorithm.
func HashFileWith(path, algorithm string) (hashes *Hashes, size int64, err error) {
	hashes = NewHashes(algorithm)
	size, err = copyFileTo(path, hashes.Writer())
	if err != nil {
		return nil, 0, err
	}
	return hashes, size, nil
}
