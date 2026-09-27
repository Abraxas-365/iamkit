// Package cryptox seals small secrets (IdP client secrets, TOTP seeds) for
// storage at rest with AES-256-GCM.
//
// Sealed values are self-describing: "v1:<keyid>:<base64url(nonce|ciphertext)>".
// The key ID is the first 8 hex characters of SHA-256(key), so rotating keys
// needs no separate registry: the current key seals, old keys only open.
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

const version = "v1"

// Sealer encrypts with its current key and decrypts with any known key. The
// zero value (no key configured) fails every operation with an internal error
// so deployments without IAMKIT_ENCRYPTION_KEY keep working until a feature
// that needs encryption is used.
type Sealer struct {
	current string
	keys    map[string]cipher.AEAD
}

// New builds a Sealer from the current key and optional decrypt-only keys,
// each 32 raw bytes.
func New(current []byte, old ...[]byte) (*Sealer, error) {
	s := &Sealer{keys: map[string]cipher.AEAD{}}
	for i, key := range append([][]byte{current}, old...) {
		if len(key) != 32 {
			return nil, errx.Validation("encryption keys must be 32 bytes")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, errx.Wrap(err, "invalid encryption key", errx.TypeValidation)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errx.Wrap(err, "invalid encryption key", errx.TypeValidation)
		}
		id := KeyID(key)
		if i == 0 {
			s.current = id
		}
		s.keys[id] = aead
	}
	return s, nil
}

// Parse reads IAMKIT_ENCRYPTION_KEY (standard base64 of 32 bytes) and
// IAMKIT_ENCRYPTION_KEYS_OLD (comma-separated base64 keys). An empty current
// key returns a disabled Sealer, not an error.
func Parse(current, old string) (*Sealer, error) {
	if strings.TrimSpace(current) == "" {
		if strings.TrimSpace(old) != "" {
			return nil, errx.Validation("IAMKIT_ENCRYPTION_KEYS_OLD requires IAMKIT_ENCRYPTION_KEY")
		}
		return &Sealer{}, nil
	}
	decode := func(raw string) ([]byte, error) {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
		if err != nil || len(key) != 32 {
			return nil, errx.Validation("encryption keys must be base64-encoded 32 bytes")
		}
		return key, nil
	}
	key, err := decode(current)
	if err != nil {
		return nil, err
	}
	var previous [][]byte
	for _, raw := range strings.Split(old, ",") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		k, err := decode(raw)
		if err != nil {
			return nil, err
		}
		previous = append(previous, k)
	}
	return New(key, previous...)
}

// KeyID names a key without revealing it.
func KeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:4])
}

// Enabled reports whether a current key is configured.
func (s *Sealer) Enabled() bool { return s != nil && s.current != "" }

func disabled() error { return errx.Internal("encryption key not configured") }

// Seal encrypts plain with the current key. Without a configured key it
// returns a business error so an operator storing a secret learns why.
func (s *Sealer) Seal(plain []byte) (string, error) {
	if !s.Enabled() {
		return "", errx.Business("storing secrets requires IAMKIT_ENCRYPTION_KEY to be configured")
	}
	aead := s.keys[s.current]
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", errx.Wrap(err, "encryption failed", errx.TypeInternal)
	}
	// The version and key ID are authenticated as additional data so a
	// ciphertext cannot be relabelled to another key.
	prefix := version + ":" + s.current
	out := aead.Seal(nonce, nonce, plain, []byte(prefix))
	return prefix + ":" + base64.RawURLEncoding.EncodeToString(out), nil
}

// Open decrypts a value sealed with the current or any old key.
func (s *Sealer) Open(sealed string) ([]byte, error) {
	if s == nil || len(s.keys) == 0 {
		return nil, disabled()
	}
	parts := strings.SplitN(sealed, ":", 3)
	if len(parts) != 3 || parts[0] != version {
		return nil, errx.Internal("sealed value has an unknown format")
	}
	aead, ok := s.keys[parts[1]]
	if !ok {
		return nil, errx.Internal("sealed value uses an unknown encryption key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(raw) < aead.NonceSize() {
		return nil, errx.Internal("sealed value is corrupt")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], []byte(parts[0]+":"+parts[1]))
	if err != nil {
		return nil, errx.Internal("sealed value failed authentication")
	}
	return plain, nil
}
