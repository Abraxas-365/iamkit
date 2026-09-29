package oauthfosite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/ory/fosite/token/jwt"
)

// LogoutSender delivers OpenID Connect Back-Channel Logout tokens: a JWT
// (typ logout+jwt) signed with the environment's key, POSTed as
// logout_token over the guarded transport. Any 2xx is delivered.
type LogoutSender struct {
	Keys   signing.Keyring
	Issuer string
	client *http.Client
}

var _ oauth.LogoutSender = (*LogoutSender)(nil)

// logoutTokenTTL bounds how long a relying party may accept a logout token.
const logoutTokenTTL = 2 * time.Minute

// NewLogoutSender dials through transport (nil: public addresses only).
func NewLogoutSender(keys signing.Keyring, issuer string, transport http.RoundTripper) *LogoutSender {
	if transport == nil {
		transport = GuardedTransport()
	}
	return &LogoutSender{Keys: keys, Issuer: issuer, client: &http.Client{Transport: transport, Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Token is the signed logout token of n.
func (s *LogoutSender) Token(ctx context.Context, n oauth.LogoutNotification) (string, error) {
	now := time.Now()
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", errx.Wrap(err, "generate logout token id", errx.TypeInternal)
	}
	claims := jwt.MapClaims{
		"iss":            s.Issuer,
		"aud":            n.Client.String(),
		"iat":            now.Unix(),
		"exp":            now.Add(logoutTokenTTL).Unix(),
		"jti":            hex.EncodeToString(jti),
		"sub":            n.Subject.String(),
		"sid":            n.Session.String(),
		"environment_id": n.Environment.String(),
		"events":         map[string]any{oauth.BackchannelLogoutEvent: map[string]any{}},
	}
	header := &jwt.Headers{Extra: map[string]any{"typ": "logout+jwt"}}
	token, _, err := Signer{Keys: s.Keys, Environment: n.Environment}.Generate(ctx, claims, header)
	if err != nil {
		return "", errx.Wrap(err, "sign logout token", errx.TypeInternal)
	}
	return token, nil
}

func (s *LogoutSender) Send(ctx context.Context, n oauth.LogoutNotification) error {
	token, err := s.Token(ctx, n)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URI, strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if err != nil {
		return errx.Validation("invalid back-channel logout URI")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")
	res, err := s.client.Do(req)
	if err != nil {
		return errx.External("back-channel logout request failed")
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return errx.External("back-channel logout answered HTTP " + strconv.Itoa(res.StatusCode))
	}
	return nil
}
