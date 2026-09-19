package authjwt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

type Codec struct {
	key    *rsa.PrivateKey
	issuer string
}

func New(key *rsa.PrivateKey, issuer string) *Codec { return &Codec{key, issuer} }

// claims is the JWT payload — all ID fields remain plain strings for JWT serialization.
type claims struct {
	identity.Access
	Purpose       string `json:"purpose"`
	SessionID     string `json:"sid,omitempty"`
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	ActorID       string `json:"actor_id,omitempty"`
	jwt.RegisteredClaims
}

func (c *Codec) KeyID() string {
	der, _ := x509.MarshalPKIXPublicKey(&c.key.PublicKey)
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}
func (c *Codec) JWKS() any {
	return map[string]any{"keys": []map[string]any{{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": c.KeyID(), "n": base64.RawURLEncoding.EncodeToString(c.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(c.key.E)).Bytes())}}}
}
func (c *Codec) Sign(input authentication.Token) (string, error) {
	payload := claims{
		Access:        input.Access,
		Purpose:       input.Purpose,
		SessionID:     input.SessionID.String(),
		OAuthClientID: input.OAuthClientID.String(),
		ActorID:       input.ActorID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   input.Subject.String(),
			Issuer:    c.issuer,
			Audience:  input.Audience,
			ID:        input.ID,
			IssuedAt:  jwt.NewNumericDate(time.Unix(input.IssuedAt, 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(input.NotBefore, 0)),
			ExpiresAt: jwt.NewNumericDate(time.Unix(input.ExpiresAt, 0)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	token.Header["kid"] = c.KeyID()
	raw, err := token.SignedString(c.key)
	if err != nil {
		return "", errx.Wrap(err, "sign access token", errx.TypeInternal)
	}
	return raw, nil
}
func (c *Codec) Verify(raw, audience string) (authentication.Token, error) {
	return c.parse(raw, jwt.WithAudience(audience))
}
func (c *Codec) VerifySelf(raw string) (authentication.Token, error) {
	return c.parse(raw)
}

func mustParse[T any](s string) identity.ID[T] {
	if s == "" || s == "00000000-0000-0000-0000-000000000000" {
		return identity.ID[T]{}
	}
	id, _ := identity.ParseID[T](s)
	return id
}

func (c *Codec) parse(raw string, extra ...jwt.ParserOption) (authentication.Token, error) {
	payload := &claims{}
	opts := append([]jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(c.issuer), jwt.WithExpirationRequired()}, extra...)
	token, err := jwt.ParseWithClaims(raw, payload, func(*jwt.Token) (any, error) { return &c.key.PublicKey, nil }, opts...)
	if err != nil || !token.Valid {
		return authentication.Token{}, errx.Unauthorized("invalid credentials or access token")
	}
	out := authentication.Token{
		Access:        payload.Access,
		Purpose:       payload.Purpose,
		SessionID:     mustParseSession(payload.SessionID),
		OAuthClientID: mustParseClient(payload.OAuthClientID),
		ActorID:       mustParseOperator(payload.ActorID),
		Subject:       mustParseUser(payload.Subject),
		Issuer:        payload.Issuer,
		Audience:      []string(payload.Audience),
		ID:            payload.ID,
		ExpiresAt:     payload.ExpiresAt.Unix(),
	}
	if payload.IssuedAt != nil {
		out.IssuedAt = payload.IssuedAt.Unix()
	}
	if payload.NotBefore != nil {
		out.NotBefore = payload.NotBefore.Unix()
	}
	return out, nil
}

// Typed parse helpers (needed because tag types are unexported).
func mustParseSession(s string) identity.SessionID {
	if s == "" {
		return identity.SessionID{}
	}
	id, _ := identity.ParseSessionID(s)
	return id
}
func mustParseClient(s string) identity.ClientID {
	if s == "" {
		return identity.ClientID{}
	}
	id, _ := identity.ParseClientID(s)
	return id
}
func mustParseOperator(s string) identity.OperatorID {
	if s == "" {
		return identity.OperatorID{}
	}
	id, _ := identity.ParseOperatorID(s)
	return id
}
func mustParseUser(s string) identity.UserID {
	if s == "" {
		return identity.UserID{}
	}
	id, _ := identity.ParseUserID(s)
	return id
}

var _ authentication.TokenCodec = (*Codec)(nil)
