package fedoidc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
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
	if c.Sealed != "" {
		transport = p.Guarded
		if transport == nil {
			transport = GuardedTransport()
		}
	}
	client := &http.Client{Transport: transport, Timeout: config.ExternalHTTPTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return oidc.ClientContext(ctx, client)
}

func (p Provider) config(ctx context.Context, c federation.Connection) (*oidc.Provider, *oauth2.Config, error) {
	secret, err := p.secret(c)
	if err != nil {
		return nil, nil, err
	}
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, nil, errx.Wrap(err, "provider discovery failed", errx.TypeExternal)
	}
	endpoint := provider.Endpoint()
	for _, raw := range []string{endpoint.AuthURL, endpoint.TokenURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.User != nil {
			return nil, nil, errx.Validation("provider endpoints must use HTTPS")
		}
	}
	return provider, &oauth2.Config{ClientID: c.Client, ClientSecret: secret, Endpoint: endpoint, RedirectURL: p.Issuer + "/identity/v1/federation/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, nil
}
func (Provider) Verifier() string { return oauth2.GenerateVerifier() }
func (p Provider) Authorize(ctx context.Context, c federation.Connection, state, nonce, verifier string) (string, error) {
	_, config, err := p.config(p.context(ctx, c), c)
	if err != nil {
		return "", err
	}
	return config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}
func (p Provider) Verify(ctx context.Context, c federation.Connection, code, nonce, verifier string) (federation.Claims, error) {
	ctx = p.context(ctx, c)
	provider, config, err := p.config(ctx, c)
	if err != nil {
		return federation.Claims{}, err
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return federation.Claims{}, errx.Unauthorized("provider exchange rejected")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return federation.Claims{}, errx.Unauthorized("provider ID token required")
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: c.Client}).Verify(ctx, raw)
	if err != nil || verified.Nonce != nonce {
		return federation.Claims{}, errx.Unauthorized("invalid provider identity")
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err = verified.Claims(&claims); err != nil {
		return federation.Claims{}, errx.Unauthorized("invalid provider identity")
	}
	return federation.Claims{Subject: verified.Subject, Email: claims.Email, EmailVerified: flag(claims.EmailVerified), Name: claims.Name}, nil
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
func GuardedTransport() http.RoundTripper {
	dialer := &net.Dialer{Timeout: config.ExternalHTTPTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(host); ip == nil || !Public(ip) {
			// A plain error: discovery wraps it as 502, the provider being
			// misconfigured rather than the caller unauthorized.
			return errNotPublic
		}
		return nil
	}}
	return &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: config.ExternalHTTPTimeout, ResponseHeaderTimeout: config.ExternalHTTPTimeout, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true}
}

var errNotPublic = errors.New("provider address is not public")

var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// Public reports whether ip is a globally routable unicast address.
func Public(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !sharedAddressSpace.Contains(ip)
}

var _ federation.Provider = Provider{}
