package fedoidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
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

// gitHubClaims reads the GitHub user: its numeric ID is the subject (the
// login can be renamed), and the email is the primary one only when GitHub
// verified it.
func gitHubClaims(ctx context.Context, client *http.Client) (federation.Claims, error) {
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := gitHub(ctx, client, "/user", &user); err != nil {
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
	if err := gitHub(ctx, client, "/user/emails", &emails); err != nil {
		return federation.Claims{}, err
	}
	out := federation.Claims{Subject: strconv.FormatInt(user.ID, 10), Name: user.Name}
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

func gitHub(ctx context.Context, client *http.Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GitHubEndpoints.API+path, nil)
	if err != nil {
		return errx.Internal("provider request")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return federation.ErrProviderUnavailable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errx.Unauthorized("provider rejected the identity request")
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxProviderResponse)).Decode(out) != nil {
		return errx.Unauthorized("invalid provider identity")
	}
	return nil
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
