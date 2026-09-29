package oauthfosite

import (
	"context"
	"errors"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/ory/fosite/token/jwt"
)

// Hints verifies id_token_hint values: ID tokens this issuer signed with a
// published key (the deployment key, or a key of the token's environment). An expired token is still a valid hint (OpenID
// Connect RP-Initiated Logout); a bad signature or foreign issuer is not.
type Hints struct {
	Keys   signing.Keyring
	Issuer string
}

func (h Hints) Parse(ctx context.Context, raw string) (oauth.IDTokenHint, error) {
	invalid := errx.Validation("invalid id_token_hint")
	var verifier signing.Verifier
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if string(t.Method) != "RS256" {
			return nil, errors.New("unexpected signing method")
		}
		kid, _ := t.Header["kid"].(string)
		key, err := h.Keys.Verifier(ctx, kid)
		if err != nil {
			return nil, err
		}
		verifier = key
		return key.Public, nil
	})
	if err != nil {
		var v *jwt.ValidationError
		if !errors.As(err, &v) || v.Errors != jwt.ValidationErrorExpired {
			return oauth.IDTokenHint{}, invalid
		}
	}
	if token == nil || token.Claims == nil {
		return oauth.IDTokenHint{}, invalid
	}
	claims = token.Claims
	if iss, _ := claims["iss"].(string); iss != h.Issuer {
		return oauth.IDTokenHint{}, invalid
	}
	sub, _ := claims["sub"].(string)
	user, err := identity.ParseUserID(sub)
	if err != nil {
		return oauth.IDTokenHint{}, invalid
	}
	env, _ := claims["environment_id"].(string)
	environment, err := identity.ParseEnvironmentID(env)
	if err != nil {
		return oauth.IDTokenHint{}, invalid
	}
	if !verifier.Allows(environment) {
		return oauth.IDTokenHint{}, invalid
	}
	out := oauth.IDTokenHint{Environment: environment, Subject: user}
	if sid, ok := claims["sid"].(string); ok {
		if out.Session, err = identity.ParseSessionID(sid); err != nil {
			return oauth.IDTokenHint{}, invalid
		}
	}
	switch aud := claims["aud"].(type) {
	case string:
		out.Clients = []string{aud}
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				out.Clients = append(out.Clients, s)
			}
		}
	}
	if len(out.Clients) == 0 {
		return oauth.IDTokenHint{}, invalid
	}
	return out, nil
}

var _ oauth.Hints = Hints{}
