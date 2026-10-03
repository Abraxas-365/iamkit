package authjwt

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

// Codec signs with the key the keyring names for the token's environment
// (its active key, else the deployment key) and verifies by kid.
type Codec struct {
	keys   signing.Keyring
	issuer string
}

func New(keys signing.Keyring, issuer string) *Codec { return &Codec{keys, issuer} }

// actor is the RFC 8693 act claim.
type actor struct {
	Subject string `json:"sub"`
}

// claims is the JWT payload — all ID fields remain plain strings for JWT serialization.
type claims struct {
	identity.Access
	Purpose       string `json:"purpose"`
	SessionID     string `json:"sid,omitempty"`
	OAuthClientID string `json:"oauth_client_id,omitempty"`
	ActorID       string `json:"actor_id,omitempty"`
	// Act is the RFC 8693 actor: the service account impersonating.
	Act *actor   `json:"act,omitempty"`
	AMR []string `json:"amr,omitempty"`
	// NumericDate accepts the float form fosite writes (1.7e+09).
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	Scopes   []string         `json:"scp,omitempty"`
	jwt.RegisteredClaims
}

// JWKS is every published key: the deployment key and every environment
// key not retired.
func (c *Codec) JWKS(ctx context.Context) (any, error) {
	keys, err := c.keys.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"keys": keys}, nil
}
func (c *Codec) Sign(ctx context.Context, input authentication.Token) (string, error) {
	key, err := c.keys.Signer(ctx, input.EnvironmentID)
	if err != nil {
		return "", err
	}
	payload := claims{
		Access:        input.Access,
		Purpose:       input.Purpose,
		SessionID:     text(input.SessionID),
		OAuthClientID: text(input.OAuthClientID),
		ActorID:       text(input.ActorID),
		AMR:           input.AMR,
		Scopes:        input.Scopes,
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
	if !input.ActorAccount.IsZero() {
		payload.Act = &actor{Subject: input.ActorAccount.String()}
	}
	if input.AuthTime != 0 {
		payload.AuthTime = jwt.NewNumericDate(time.Unix(input.AuthTime, 0))
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	token.Header["kid"] = key.ID
	raw, err := token.SignedString(key.Private)
	if err != nil {
		return "", errx.Wrap(err, "sign access token", errx.TypeInternal)
	}
	return raw, nil
}
func (c *Codec) Verify(ctx context.Context, raw, audience string) (authentication.Token, error) {
	return c.parse(ctx, raw, jwt.WithAudience(audience))
}
func (c *Codec) VerifySelf(ctx context.Context, raw string) (authentication.Token, error) {
	return c.parse(ctx, raw)
}

func mustParse[T any](s string) identity.ID[T] {
	if s == "" || s == "00000000-0000-0000-0000-000000000000" {
		return identity.ID[T]{}
	}
	id, _ := identity.ParseID[T](s)
	return id
}

// text is an optional ID claim: empty (so omitempty drops it) when unset,
// never the nil UUID, which a relying party would read as present
// (actor_id → impersonated, sid on a machine token).
func text[T any](id identity.ID[T]) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}

func (c *Codec) parse(ctx context.Context, raw string, extra ...jwt.ParserOption) (authentication.Token, error) {
	payload := &claims{}
	opts := append([]jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(c.issuer), jwt.WithExpirationRequired()}, extra...)
	var verifier signing.Verifier
	var keyErr error
	token, err := jwt.ParseWithClaims(raw, payload, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, err := c.keys.Verifier(ctx, kid)
		if err != nil {
			keyErr = err
			return nil, err
		}
		verifier = key
		return key.Public, nil
	}, opts...)
	// A key store outage is not a bad token.
	if errx.IsServerError(keyErr) {
		return authentication.Token{}, keyErr
	}
	// An environment key only vouches for its own environment's tokens.
	if err != nil || !token.Valid || !verifier.Allows(payload.EnvironmentID) {
		return authentication.Token{}, errx.Unauthorized("invalid credentials or access token")
	}
	out := authentication.Token{
		Access:        payload.Access,
		Purpose:       payload.Purpose,
		SessionID:     mustParseSession(payload.SessionID),
		OAuthClientID: mustParseClient(payload.OAuthClientID),
		ActorID:       mustParseOperator(payload.ActorID),
		AMR:           payload.AMR,
		Scopes:        payload.Scopes,
		Subject:       mustParseUser(payload.Subject),
		Issuer:        payload.Issuer,
		Audience:      []string(payload.Audience),
		ID:            payload.ID,
		ExpiresAt:     payload.ExpiresAt.Unix(),
	}
	if payload.Act != nil {
		account, err := identity.ParseAccountID(payload.Act.Subject)
		if err != nil {
			return authentication.Token{}, errx.Unauthorized("invalid credentials or access token")
		}
		out.ActorAccount = account
	}
	if payload.IssuedAt != nil {
		out.IssuedAt = payload.IssuedAt.Unix()
	}
	if payload.AuthTime != nil {
		out.AuthTime = payload.AuthTime.Unix()
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
