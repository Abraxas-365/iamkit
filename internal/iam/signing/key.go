// Package signing owns the keys IAMKit signs tokens with: the deployment
// key (JWT_PRIVATE_KEY_PATH), used by every environment without its own,
// and per-environment keys an operator creates, activates and retires.
package signing

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Key states. A next key is published in the JWKS but does not sign yet;
// the active key signs the environment's tokens; a retiring key (replaced
// by another) still verifies tokens it signed until it is retired.
const (
	StateNext     = "next"
	StateActive   = "active"
	StateRetiring = "retiring"
	StateRetired  = "retired"
)

// Audit actions.
const (
	ActionCreate   = "signing_key.create"
	ActionActivate = "signing_key.activate"
	ActionRetire   = "signing_key.retire"
)

// Algorithm is the only signing algorithm (RSA 2048, SHA-256).
const Algorithm = "RS256"

// Key is an environment signing key as operators see it; the private key
// never leaves the service.
type Key struct {
	ID          string                 `json:"kid" db:"id"`
	Environment identity.EnvironmentID `json:"environment_id" db:"environment_id"`
	Algorithm   string                 `json:"alg" db:"algorithm"`
	State       string                 `json:"state" db:"state"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	ActivatedAt *time.Time             `json:"activated_at,omitempty" db:"activated_at"`
	// RetireAfter is when a retiring key has outlived every token it
	// signed; retiring it earlier needs force.
	RetireAfter *time.Time `json:"retire_after,omitempty" db:"retire_after"`
	RetiredAt   *time.Time `json:"retired_at,omitempty" db:"retired_at"`
	PublicJWK   *JWK       `json:"public_jwk,omitempty" db:"-"`
}

// Stored is a key with its key material: the sealed private key and the
// PKIX DER public key.
type Stored struct {
	Key
	Sealed string `db:"private_sealed"`
	Public []byte `db:"public_der"`
}

// JWK is a published RSA public key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewJWK describes public as a signing JWK.
func NewJWK(public *rsa.PublicKey) JWK {
	return JWK{Kty: "RSA", Use: "sig", Alg: Algorithm, Kid: KeyID(public), N: base64.RawURLEncoding.EncodeToString(public.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes())}
}

// KeyID is the kid of a public key: the first 16 bytes of the SHA-256 of
// its PKIX DER, base64url. The deployment key's kid has always been this.
func KeyID(public *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(public)
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}

// Signer is the key an environment's tokens are signed with now.
type Signer struct {
	ID      string
	Private *rsa.PrivateKey
}

// Certificate is the signer's self-signed certificate for XML signatures
// (SAML). It is derived from the key alone — fixed validity, serial from
// the key ID, deterministic RSA PKCS #1 v1.5 signature — so every replica
// publishes the same one; rotating the key changes it.
func (s Signer) Certificate() (*x509.Certificate, error) {
	serial := sha256.Sum256([]byte(s.ID))
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serial[:16]),
		Subject:      pkix.Name{CommonName: "IAMKit SAML " + s.ID},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(nil, template, template, &s.Private.PublicKey, s.Private)
	if err != nil {
		return nil, errx.Wrap(err, "SAML certificate failed", errx.TypeInternal)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errx.Wrap(err, "SAML certificate failed", errx.TypeInternal)
	}
	return cert, nil
}

// Verifier is a published public key. Environment is zero for the
// deployment key, which verifies tokens of every environment; an
// environment key only verifies its own environment's tokens.
type Verifier struct {
	ID          string
	Public      *rsa.PublicKey
	Environment identity.EnvironmentID
}

// Allows reports whether the key may have signed a token of environment.
func (v Verifier) Allows(environment identity.EnvironmentID) bool {
	return v.Environment.IsZero() || v.Environment == environment
}

// Retire retires a key. Force retires a retiring key before RetireAfter
// (a compromised key): tokens it signed stop validating at once.
type Retire struct {
	Force bool `json:"force"`
}

// Mutation is the audit context of a key change.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// ErrKeyInUse refuses to retire a key tokens may still carry.
func ErrKeyInUse(message string) error {
	e := errx.Conflict(message)
	e.Code = "KEY_IN_USE"
	return e
}
