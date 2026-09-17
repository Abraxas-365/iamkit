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
	payload := claims{Access: input.Access, Purpose: input.Purpose, SessionID: input.SessionID, OAuthClientID: input.OAuthClientID, ActorID: input.ActorID, RegisteredClaims: jwt.RegisteredClaims{Subject: input.Subject, Issuer: c.issuer, Audience: input.Audience, ID: input.ID, IssuedAt: jwt.NewNumericDate(time.Unix(input.IssuedAt, 0)), NotBefore: jwt.NewNumericDate(time.Unix(input.NotBefore, 0)), ExpiresAt: jwt.NewNumericDate(time.Unix(input.ExpiresAt, 0))}}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	token.Header["kid"] = c.KeyID()
	raw, err := token.SignedString(c.key)
	if err != nil {
		return "", errx.Wrap(err, "sign access token", errx.TypeInternal)
	}
	return raw, nil
}
func (c *Codec) Verify(raw, audience string) (authentication.Token, error) {
	payload := &claims{}
	token, err := jwt.ParseWithClaims(raw, payload, func(*jwt.Token) (any, error) { return &c.key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(c.issuer), jwt.WithAudience(audience), jwt.WithExpirationRequired())
	if err != nil || !token.Valid {
		return authentication.Token{}, errx.Unauthorized("invalid credentials or access token")
	}
	out := authentication.Token{Access: payload.Access, Purpose: payload.Purpose, SessionID: payload.SessionID, OAuthClientID: payload.OAuthClientID, ActorID: payload.ActorID, Subject: payload.Subject, Issuer: payload.Issuer, Audience: []string(payload.Audience), ID: payload.ID, ExpiresAt: payload.ExpiresAt.Unix()}
	if payload.IssuedAt != nil {
		out.IssuedAt = payload.IssuedAt.Unix()
	}
	if payload.NotBefore != nil {
		out.NotBefore = payload.NotBefore.Unix()
	}
	return out, nil
}

var _ authentication.TokenCodec = (*Codec)(nil)
