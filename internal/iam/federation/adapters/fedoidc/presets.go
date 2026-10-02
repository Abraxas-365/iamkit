package fedoidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/golang-jwt/jwt/v5"
)

// MicrosoftIssuer is the issuer of Microsoft ID tokens for a tenant.
func MicrosoftIssuer(tenant string) string {
	return "https://login.microsoftonline.com/" + tenant + "/v2.0"
}

// microsoftVerified decides whether a Microsoft email is verified. The
// email claim of a work or school account is an attribute its tenant's
// administrators may set to anything, so it counts only when the optional
// xms_edov claim says the tenant verified the email's domain. Personal
// accounts sign in with a verified email. Single-tenant connections trust
// their own tenant's directory like any OIDC provider (unknown, not false).
func microsoftVerified(o federation.Options, tenant, email string, edov any) *bool {
	yes, no := true, false
	switch {
	case email == "":
		return nil
	case tenant == federation.ConsumerTenant:
		return &yes
	case edov != nil:
		return flag(edov)
	case o.MultiTenant():
		return &no
	}
	return nil
}

// GitHubEndpoints are GitHub's OAuth 2.0 and API endpoints; tests replace
// them.
var GitHubEndpoints = struct{ Auth, Token, API string }{
	Auth:  "https://github.com/login/oauth/authorize",
	Token: "https://github.com/login/oauth/access_token",
	API:   "https://api.github.com",
}

// maxProviderResponse bounds a provider API response.
const maxProviderResponse = 1 << 20

// gitHubEndpoints are the endpoints of a GitHub connection: github.com, or
// the GitHub Enterprise Server at the connection's base URL (its REST API
// under /api/v3).
func gitHubEndpoints(c federation.Connection) (auth, token, api string) {
	if c.Provider == federation.ProviderGitHubEnterprise {
		base := c.Options.BaseURL
		return base + "/login/oauth/authorize", base + "/login/oauth/access_token", base + "/api/v3"
	}
	return GitHubEndpoints.Auth, GitHubEndpoints.Token, GitHubEndpoints.API
}

// gitHub reports whether the connection talks to GitHub's OAuth 2.0 and
// REST API (github.com or Enterprise Server).
func gitHub(c federation.Connection) bool {
	return c.Provider == federation.ProviderGitHub || c.Provider == federation.ProviderGitHubEnterprise
}

// gitHubClaims reads the GitHub user from the REST API at api: its numeric
// ID is the subject (the login can be renamed), and the email is the
// primary one only when GitHub verified it.
func gitHubClaims(ctx context.Context, client *http.Client, api string) (federation.Claims, error) {
	var user struct {
		ID     int64  `json:"id"`
		Login  string `json:"login"`
		Name   string `json:"name"`
		Avatar string `json:"avatar_url"`
	}
	if err := getJSON(ctx, client, api+"/user", true, &user); err != nil {
		return federation.Claims{}, err
	}
	if user.ID <= 0 {
		return federation.Claims{}, errx.Unauthorized("invalid provider identity")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, client, api+"/user/emails", true, &emails); err != nil {
		return federation.Claims{}, err
	}
	out := federation.Claims{Subject: strconv.FormatInt(user.ID, 10), Name: user.Name, Picture: user.Avatar}
	if out.Name == "" {
		out.Name = user.Login
	}
	for _, e := range emails {
		if e.Primary {
			verified := e.Verified
			out.Email, out.EmailVerified = e.Email, &verified
		}
	}
	return out, nil
}

// getJSON reads a provider API response (GitHub's when github) into out.
func getJSON(ctx context.Context, client *http.Client, address string, github bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return errx.Internal("provider request")
	}
	req.Header.Set("Accept", "application/json")
	if github {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	resp, err := client.Do(req)
	if err != nil {
		return federation.ErrProviderUnavailable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errx.Unauthorized("provider rejected the identity request")
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxProviderResponse))
	decoder.UseNumber() // numeric subjects keep every digit
	if decoder.Decode(out) != nil {
		return errx.Unauthorized("invalid provider identity")
	}
	return nil
}

// oauth2Claims reads an OAuth 2.0 provider's userinfo endpoint and maps it
// with the connection's claim mapping. The subject may be a string or a
// number; the email is verified only when the mapped member is true.
func oauth2Claims(ctx context.Context, client *http.Client, c federation.Connection) (federation.Claims, error) {
	m := c.Options.Claims
	if m == nil {
		return federation.Claims{}, errx.Internal("the OAuth 2.0 connection has no claim mapping")
	}
	var raw any
	if err := getJSON(ctx, client, c.Options.UserinfoURL, false, &raw); err != nil {
		return federation.Claims{}, err
	}
	var out federation.Claims
	switch v := member(raw, m.Subject).(type) {
	case string:
		out.Subject = v
	case json.Number:
		out.Subject = v.String()
	case float64:
		out.Subject = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if out.Subject == "" || len(out.Subject) > 255 {
		return federation.Claims{}, errx.Unauthorized("invalid provider identity")
	}
	if m.Email != "" {
		out.Email, _ = member(raw, m.Email).(string)
		no := false
		out.EmailVerified = &no
		if m.EmailVerified != "" {
			if v := flag(member(raw, m.EmailVerified)); v != nil {
				out.EmailVerified = v
			}
		}
	}
	if m.Name != "" {
		out.Name, _ = member(raw, m.Name).(string)
	}
	if m.Picture != "" {
		out.Picture, _ = member(raw, m.Picture).(string)
	}
	return out, nil
}

// member follows a dotted path through JSON objects.
func member(v any, path string) any {
	for _, key := range strings.Split(path, ".") {
		object, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = object[key]
	}
	return v
}

// appleSecret is the client secret of a Sign in with Apple exchange: a
// short-lived ES256 JWT signed with the connection's private key.
func appleSecret(c federation.Connection, pem string, now time.Time) (string, error) {
	key, err := federation.ParseAppleKey(pem)
	if err != nil {
		return "", errx.Internal("the Apple private key of the connection is invalid")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    c.Options.Team,
		Subject:   c.Client,
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	})
	token.Header["kid"] = c.Options.Key
	return token.SignedString(key)
}
