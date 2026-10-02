package user

import (
	"encoding/json"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Audit actions of machine user keys.
const (
	ActionKeyAdded   = "user.key_added"
	ActionKeyRemoved = "user.key_removed"
)

// MaxKeys is how many keys one machine user may hold.
const MaxKeys = 10

// Key is a machine user's public key: the user signs a JWT with the private
// half and trades it at /oauth/token (RFC 7523 JWT-bearer grant) for an
// access token. The key's ID is the kid of those assertions.
type Key struct {
	ID         identity.UserKeyID `json:"id" db:"id"`
	User       identity.UserID    `json:"user_id" db:"user_id"`
	PublicKey  json.RawMessage    `json:"public_key" db:"public_jwk"`
	ExpiresAt  time.Time          `json:"expires_at" db:"expires_at"`
	LastUsedAt *time.Time         `json:"last_used_at" db:"last_used_at"`
	CreatedAt  time.Time          `json:"created_at" db:"created_at"`
}

// IssuedKey is a new key. When IAMKit generated the pair, PrivateKey (PEM,
// PKCS #8) is returned only here and never stored.
type IssuedKey struct {
	Key
	PrivateKey string `json:"private_key,omitempty"`
}

// NewKey adds a key: PublicKey is an RSA (2048 bits or more) or EC public
// JSON Web Key; without it IAMKit generates an RSA 2048 pair. ExpiresIn is
// a Go duration from 1h to 8760h or "never" (default 8760h).
type NewKey struct {
	PublicKey json.RawMessage `json:"public_key"`
	ExpiresIn *string         `json:"expires_in"`
}

// KeyTTL is the default lifetime of a key.
const KeyTTL = identity.MaxTTL

func (n NewKey) Validate() error {
	if n.Uploaded() {
		if _, err := identity.ParsePublicJWK(n.PublicKey); err != nil {
			return err
		}
	}
	if n.ExpiresIn == nil || *n.ExpiresIn == "" {
		return nil
	}
	_, err := identity.ParseTTL(n.ExpiresIn)
	return err
}

// Uploaded reports whether the caller brought its own public key.
func (n NewKey) Uploaded() bool {
	return len(n.PublicKey) > 0 && string(n.PublicKey) != "null"
}

// TTL is the key's lifetime (validated).
func (n NewKey) TTL() time.Duration {
	if n.ExpiresIn == nil || *n.ExpiresIn == "" {
		return KeyTTL
	}
	ttl, _ := identity.ParseTTL(n.ExpiresIn)
	return ttl
}

// ErrTooManyKeys is answered when a machine user already holds MaxKeys.
func ErrTooManyKeys() error {
	return errx.Business("a machine user can hold at most 10 keys")
}
