package fedoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider performs OIDC discovery, authorization and code exchange.
//
// Secrets: legacy connections reference a deployment variable (secret_env)
// that must match an approved FEDERATION_CREDENTIAL_BINDINGS entry, because
// those variables are shared by the whole deployment. Sealed secrets belong
// to one connection row, so they need no approval; instead, since operators
// may then point IAMKit at any issuer, their outbound requests use Guarded,
// which refuses private, loopback and link-local addresses.
type Provider struct {
	Issuer string
	Cipher federation.Cipher
	// Transport serves legacy connections; nil uses http.DefaultTransport.
	Transport http.RoundTripper
	// Guarded serves sealed-secret connections; nil uses GuardedTransport().
	Guarded http.RoundTripper
	// Redirect, when set, replaces the federation callback as the redirect
	// URI (operator single sign-on has its own callback).
	Redirect string
	// Secret, when set, is the client secret of every connection: the
	// deployment configured it, like its issuer, so it needs no approval
	// and uses Transport (the deployment's own IdP may be internal).
	Secret string
}

func (Provider) Approved(c federation.Connection) bool {
	if c.SecretEnv == "" {
		return false
	}
	var entries []struct {
		Environment string `json:"environment_id"`
		Issuer      string `json:"issuer"`
		Client      string `json:"client_id"`
		Secret      string `json:"secret_env"`
	}
	if json.Unmarshal([]byte(os.Getenv("FEDERATION_CREDENTIAL_BINDINGS")), &entries) != nil {
		return false
	}
	for _, entry := range entries {
		if entry.Environment == c.Environment.String() && entry.Issuer == c.Issuer && entry.Client == c.Client && entry.Secret == c.SecretEnv {
			return true
		}
	}
	return false
}

func (p Provider) secret(c federation.Connection) (string, error) {
	if p.Secret != "" {
		return p.Secret, nil
	}
	if c.Sealed != "" {
		if p.Cipher == nil {
			return "", errx.Internal("encryption key not configured")
		}
		plain, err := p.Cipher.Open(c.Sealed)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	if !p.Approved(c) {
		return "", errx.Forbidden("provider credential binding not approved")
	}
	secret := os.Getenv(c.SecretEnv)
	if secret == "" {
		return "", errx.Internal("provider credential is not configured")
	}
	return secret, nil
}

func (p Provider) context(ctx context.Context, c federation.Connection) context.Context {
	transport := p.Transport
	if c.Sealed != "" && p.Secret == "" {
		transport = p.Guarded
		if transport == nil {
			transport = GuardedTransport()
		}
	}
	client := &http.Client{Transport: transport, Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return oidc.ClientContext(ctx, client)
}

// session is what one authorization or callback needs: the provider's
// OIDC metadata (nil for GitHub and OAuth 2.0 connections, which have no
// ID token) and client.
type session struct {
	oidc   *oidc.Provider
	config *oauth2.Config
}

func (p Provider) session(ctx context.Context, c federation.Connection) (session, error) {
	secret, err := p.secret(c)
	if err != nil {
		return session{}, err
	}
	config := &oauth2.Config{ClientID: c.Client, ClientSecret: secret, RedirectURL: p.Callback(), Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	switch c.Provider {
	case federation.ProviderGitHub, federation.ProviderGitHubEnterprise:
		auth, token, _ := gitHubEndpoints(c)
		config.Endpoint = oauth2.Endpoint{AuthURL: auth, TokenURL: token, AuthStyle: oauth2.AuthStyleInParams}
		config.Scopes = []string{"read:user", "user:email"}
		return session{config: config}, nil
	case federation.ProviderOAuth2:
		config.Endpoint = oauth2.Endpoint{AuthURL: c.Options.AuthorizeURL, TokenURL: c.Options.TokenURL}
		config.Scopes = c.Options.Scopes
		return session{config: config}, nil
	case federation.ProviderApple:
		if config.ClientSecret, err = appleSecret(c, secret, time.Now()); err != nil {
			return session{}, err
		}
		config.Scopes = []string{oidc.ScopeOpenID, "name", "email"}
	}
	discovery := ctx
	if c.Provider == federation.ProviderMicrosoft {
		// Microsoft metadata names a per-tenant issuer ("{tenantid}" for
		// common and organizations, the tenant ID for consumers); Verify
		// checks the token's issuer against its tenant instead.
		discovery = oidc.InsecureIssuerURLContext(ctx, c.Issuer)
	}
	provider, err := oidc.NewProvider(discovery, c.Issuer)
	if err != nil {
		return session{}, federation.ErrProviderUnavailable(err)
	}
	config.Endpoint = provider.Endpoint()
	if c.Provider == federation.ProviderApple {
		config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	}
	for _, raw := range []string{config.Endpoint.AuthURL, config.Endpoint.TokenURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil {
			return session{}, errx.Validation("provider endpoints must use HTTPS")
		}
	}
	return session{oidc: provider, config: config}, nil
}

func (Provider) Verifier() string { return oauth2.GenerateVerifier() }

// Callback is the redirect URI: Redirect when set, else IAMKit's
// federation callback.
func (p Provider) Callback() string {
	if p.Redirect != "" {
		return p.Redirect
	}
	return p.Issuer + "/identity/v1/federation/callback"
}

func (p Provider) Authorize(ctx context.Context, c federation.Connection, state, nonce, verifier string) (string, error) {
	s, err := p.session(p.context(ctx, c), c)
	if err != nil {
		return "", err
	}
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	switch c.Provider {
	case federation.ProviderGitHub, federation.ProviderGitHubEnterprise, federation.ProviderOAuth2:
		// No ID token, so no nonce; state and PKCE bind the callback.
	case federation.ProviderApple:
		// Apple requires form_post when asking for the name or email, and
		// does not support PKCE: the ID token's nonce binds the callback.
		options = []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.SetAuthURLParam("response_mode", "form_post")}
	default:
		options = append(options, oidc.Nonce(nonce))
	}
	return s.config.AuthCodeURL(state, options...), nil
}

func (p Provider) Verify(ctx context.Context, c federation.Connection, code, nonce, verifier string) (federation.Claims, error) {
	ctx = p.context(ctx, c)
	s, err := p.session(ctx, c)
	if err != nil {
		return federation.Claims{}, err
	}
	var exchange []oauth2.AuthCodeOption
	if c.Provider != federation.ProviderApple {
		exchange = append(exchange, oauth2.VerifierOption(verifier))
	}
	token, err := s.config.Exchange(ctx, code, exchange...)
	if err != nil {
		return federation.Claims{}, errx.Unauthorized("provider exchange rejected")
	}
	if gitHub(c) {
		_, _, api := gitHubEndpoints(c)
		return gitHubClaims(ctx, s.config.Client(ctx, token), api)
	}
	if c.Provider == federation.ProviderOAuth2 {
		return oauth2Claims(ctx, s.config.Client(ctx, token), c)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return federation.Claims{}, errx.Unauthorized("provider ID token required")
	}
	microsoft := c.Provider == federation.ProviderMicrosoft
	verified, err := s.oidc.Verifier(&oidc.Config{ClientID: c.Client, SkipIssuerCheck: microsoft}).Verify(ctx, raw)
	if err != nil || verified.Nonce != nonce {
		return federation.Claims{}, errx.Unauthorized("invalid provider identity")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
		Tenant        string `json:"tid"`
		DomainOwner   any    `json:"xms_edov"`
		HostedDomain  string `json:"hd"`
	}
	if err = verified.Claims(&claims); err != nil {
		return federation.Claims{}, errx.Unauthorized("invalid provider identity")
	}
	out := federation.Claims{Subject: verified.Subject, Email: claims.Email, EmailVerified: flag(claims.EmailVerified), Name: claims.Name, Issuer: c.Issuer}
	if c.Provider == federation.ProviderGoogle {
		out.HostedDomain = claims.HostedDomain
		if !c.Options.AcceptsHostedDomain(claims.HostedDomain) {
			return federation.Claims{}, errx.Unauthorized("this Google account is not accepted here")
		}
	}
	if microsoft {
		if verified.Issuer != MicrosoftIssuer(claims.Tenant) || !c.Options.AcceptsTenant(claims.Tenant) {
			return federation.Claims{}, errx.Unauthorized("this Microsoft account is not accepted here")
		}
		out.EmailVerified = microsoftVerified(c.Options, claims.Tenant, claims.Email, claims.DomainOwner)
		out.Issuer = verified.Issuer // checked against the tenant above
	}
	return out, nil
}

// flag reads email_verified, which some providers send as a string. An
// unreadable value counts as false, never as absent.
func flag(v any) *bool {
	var out bool
	switch value := v.(type) {
	case nil:
		return nil
	case bool:
		out = value
	case string:
		out, _ = strconv.ParseBool(value)
	}
	return &out
}

// GuardedTransport dials only public addresses. The check runs on the
// resolved IP at connect time, so DNS rebinding cannot bypass it, and
// environment proxies are ignored because they would hide the destination.
// A refused dial is a plain error: discovery wraps it as 502, the provider
// being misconfigured rather than the caller unauthorized.
func GuardedTransport() http.RoundTripper {
	return &http.Transport{DialContext: netx.GuardedDialer().DialContext, TLSHandshakeTimeout: config.ExternalHTTPTimeout, ResponseHeaderTimeout: config.ExternalHTTPTimeout, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true}
}

// Prepare leaves OIDC and OAuth 2.0 connections as they are.
func (Provider) Prepare(_ context.Context, c federation.Connection) (federation.Connection, error) {
	return c, nil
}

// Metadata is SAML only.
func (Provider) Metadata(context.Context, federation.Connection) ([]byte, error) {
	return nil, errx.NotFound("SAML connection not found")
}

var _ federation.Provider = Provider{}
