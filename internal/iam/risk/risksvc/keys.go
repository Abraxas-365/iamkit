package risksvc

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// HashKeys is risk.Keys: HMAC-SHA256 of a login or device id under a key
// derived from the deployment secret and the environment, so a hash from
// one environment (or purpose) is meaningless in another and the stored
// attempts never reveal what was typed. Without a deployment secret it
// falls back to SHA-256 salted with the environment and purpose: still
// one-way per environment, but guessable for short low-entropy logins by
// someone who can read the table; set a secret in production.
type HashKeys struct {
	// Secret returns the deployment secret (read per call: it may change
	// only with a restart, and hashes are then not comparable across it).
	Secret func() string
}

func (k HashKeys) Hash(environment identity.EnvironmentID, purpose, value string) []byte {
	var secret string
	if k.Secret != nil {
		secret = k.Secret()
	}
	salt := "iamkit-risk:" + environment.String() + ":" + purpose
	if secret == "" {
		sum := sha256.Sum256([]byte(salt + ":" + value))
		return sum[:]
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(salt))
	key := m.Sum(nil)
	m = hmac.New(sha256.New, key)
	m.Write([]byte(value))
	return m.Sum(nil)
}
