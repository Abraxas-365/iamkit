package authjwt

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

func invalidAssertion() error { return errx.Unauthorized("invalid assertion") }

// AssertionKey reads the kid of an RFC 7523 assertion without verifying it.
func (c *Codec) AssertionKey(raw string) (identity.UserKeyID, error) {
	token, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return identity.UserKeyID{}, invalidAssertion()
	}
	kid, _ := token.Header["kid"].(string)
	key, err := identity.ParseUserKeyID(kid)
	if err != nil {
		return identity.UserKeyID{}, invalidAssertion()
	}
	return key, nil
}

// VerifyAssertion checks a machine user's JWT-bearer assertion (RFC 7523
// §3): signed by key with an algorithm of its type, iss and sub the key's
// user, aud this issuer or its token endpoint, expiring within
// config.ClientAssertionMaxAge, with a jti.
func (c *Codec) VerifyAssertion(_ context.Context, raw string, key authentication.MachineKey) (authentication.Assertion, error) {
	public, err := identity.ParsePublicJWK(key.PublicKey)
	if err != nil {
		return authentication.Assertion{}, invalidAssertion()
	}
	subject := key.User.String()
	var claims jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return public, nil },
		jwt.WithValidMethods(identity.KeyAlgorithms(public)),
		jwt.WithIssuer(subject), jwt.WithSubject(subject),
		jwt.WithAudience(c.issuer, c.issuer+"/oauth/token"),
		jwt.WithExpirationRequired(), jwt.WithLeeway(30*time.Second))
	if err != nil || !token.Valid || claims.ID == "" || len(claims.ID) > 256 {
		return authentication.Assertion{}, invalidAssertion()
	}
	expires := claims.ExpiresAt.Time
	if time.Until(expires) > config.ClientAssertionMaxAge {
		return authentication.Assertion{}, errx.Unauthorized("assertion expires too far in the future")
	}
	return authentication.Assertion{JTI: claims.ID, Expires: expires}, nil
}
