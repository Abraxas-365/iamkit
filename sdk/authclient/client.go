package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Abraxas-365/iamkit/sdk/apierror"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}
type LoginContext struct {
	EnvironmentID  string `json:"environment_id"`
	OrganizationID string `json:"organization_id"`
	ApplicationID  string `json:"application_id"`
	ResourceID     string `json:"resource_id"`
}
type PasswordLogin struct {
	LoginContext
	Email    string `json:"email"`
	Password string `json:"password"`
}
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}
type Challenge struct {
	ID        string `json:"challenge_id"`
	Message   string `json:"message"`
	ExpiresIn int    `json:"expires_in"`
}
type ChallengeVerification struct {
	LoginContext
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	Purpose     string `json:"purpose"`
	Password    string `json:"password,omitempty"`
}

func (c Client) request(ctx context.Context, path, token string, input, output any) error {
	return c.requestMethod(ctx, "POST", path, token, input, output)
}
func (c Client) requestMethod(ctx context.Context, method, path, token string, input, output any) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+"/identity/v1"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	transport := c.HTTP
	if transport == nil {
		transport = http.DefaultClient
	}
	client := *transport
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var envelope struct {
			Error apierror.Error `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&envelope) == nil && envelope.Error.Code != "" {
			envelope.Error.HTTPStatus = res.StatusCode
			return &envelope.Error
		}
		return &apierror.Error{Code: "HTTP_ERROR", Message: "identity request failed", HTTPStatus: res.StatusCode}
	}
	if output == nil || res.StatusCode == 204 {
		return nil
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(output)
}
func (c Client) Login(ctx context.Context, input PasswordLogin) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/login", "", input, &out)
	return out, err
}
func (c Client) Refresh(ctx context.Context, boundary LoginContext, refresh string) (TokenPair, error) {
	var out TokenPair
	input := struct {
		LoginContext
		Token string `json:"refresh_token"`
	}{boundary, refresh}
	err := c.request(ctx, "/refresh", "", input, &out)
	return out, err
}
func (c Client) MachineToken(ctx context.Context, secret string) (TokenPair, error) {
	if !strings.HasPrefix(secret, "ik_svc_") {
		return TokenPair{}, fmt.Errorf("service credential required")
	}
	var out TokenPair
	err := c.request(ctx, "/machine-token", secret, nil, &out)
	return out, err
}
func (c Client) InitiateChallenge(ctx context.Context, environment, email, purpose string) (Challenge, error) {
	var out Challenge
	err := c.request(ctx, "/challenges", "", map[string]string{"environment_id": environment, "email": email, "purpose": purpose}, &out)
	return out, err
}
func (c Client) VerifyChallenge(ctx context.Context, input ChallengeVerification) (TokenPair, error) {
	var out TokenPair
	err := c.request(ctx, "/challenges/verify", "", input, &out)
	return out, err
}
func (c Client) Logout(ctx context.Context, token, environment, audience string) error {
	return c.request(ctx, "/logout", token, map[string]string{"environment_id": environment, "audience": audience}, nil)
}

// Introspect enforces locally configured boundaries as well as server-side revocation.
func (c Client) Introspect(ctx context.Context, token, issuer, audience, environment, application, resource string) (*Claims, error) {
	if issuer == "" || audience == "" || environment == "" || application == "" || resource == "" {
		return nil, fmt.Errorf("expected boundaries required")
	}
	var out struct {
		Active bool   `json:"active"`
		Claims Claims `json:"claims"`
	}
	if err := c.request(ctx, "/introspect", token, map[string]string{"environment_id": environment, "audience": audience}, &out); err != nil {
		return nil, err
	}
	p := out.Claims
	hasAudience := false
	for _, v := range p.Audience {
		if v == audience {
			hasAudience = true
		}
	}
	if !out.Active || p.Issuer != issuer || !hasAudience || p.EnvironmentID != environment || p.ApplicationID != application || p.ResourceID != resource || p.Subject == "" {
		return nil, fmt.Errorf("inactive token or boundary mismatch")
	}
	if p.Purpose != "application" && p.Purpose != "machine" {
		return nil, fmt.Errorf("invalid purpose")
	}
	return &p, nil
}
