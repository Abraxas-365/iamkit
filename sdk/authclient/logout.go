package authclient

import (
	"context"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
	"github.com/golang-jwt/jwt/v5"
)

// BackchannelLogoutEvent is the events member every logout token carries.
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutToken is a verified OpenID Connect Back-Channel Logout token: the
// session SessionID of user Subject ended. End your application's session
// for SessionID (or every session of Subject).
type LogoutToken struct {
	Subject       string         `json:"sub"`
	SessionID     string         `json:"sid"`
	EnvironmentID string         `json:"environment_id"`
	ID            string         `json:"jti"`
	Events        map[string]any `json:"events"`
	Nonce         *string        `json:"nonce"`
	jwt.RegisteredClaims
}

// ValidateLogoutToken verifies the logout_token form field IAMKit POSTs to
// an OAuth client's backchannel_logout_uri: RS256 signature from keys, iss
// = issuer, aud = clientID, not expired, the back-channel logout event, a
// sid and no nonce. Answer 200 when it is valid, 400 otherwise. Replay
// protection (remembering jti until exp) is up to the caller.
func ValidateLogoutToken(ctx context.Context, raw string, keys *KeySet, issuer, clientID string) (*LogoutToken, error) {
	if keys == nil || issuer == "" || clientID == "" {
		return nil, &apierror.Error{Code: "VALIDATION", Message: "key set, issuer and client ID required", HTTPStatus: 400}
	}
	invalid := &apierror.Error{Code: "UNAUTHORIZED", Message: "invalid logout token", HTTPStatus: 400}
	out := &LogoutToken{}
	t, err := jwt.ParseWithClaims(raw, out, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		return keys.Key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(clientID), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !t.Valid {
		return nil, invalid
	}
	if _, ok := out.Events[BackchannelLogoutEvent].(map[string]any); !ok || out.Nonce != nil || out.SessionID == "" || out.Subject == "" || out.ID == "" {
		return nil, invalid
	}
	if typ, _ := t.Header["typ"].(string); typ != "" && typ != "logout+jwt" && typ != "JWT" {
		return nil, invalid
	}
	return out, nil
}
