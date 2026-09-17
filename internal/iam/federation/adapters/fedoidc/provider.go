package fedoidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Provider struct{ Issuer string }

func (Provider) Approved(c federation.Connection) bool {
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
		if entry.Environment == c.Environment && entry.Issuer == c.Issuer && entry.Client == c.Client && entry.Secret == c.SecretEnv {
			return true
		}
	}
	return false
}
func (p Provider) config(ctx context.Context, c federation.Connection) (*oidc.Provider, *oauth2.Config, error) {
	if !p.Approved(c) {
		return nil, nil, errx.Forbidden("provider credential binding not approved")
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
	secret := os.Getenv(c.SecretEnv)
	if secret == "" {
		return nil, nil, errx.Internal("provider credential is not configured")
	}
	return provider, &oauth2.Config{ClientID: c.Client, ClientSecret: secret, Endpoint: endpoint, RedirectURL: p.Issuer + "/identity/v1/federation/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}, nil
}
func httpContext(ctx context.Context) context.Context {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return oidc.ClientContext(ctx, client)
}
func (Provider) Verifier() string { return oauth2.GenerateVerifier() }
func (p Provider) Authorize(ctx context.Context, c federation.Connection, state, nonce, verifier string) (string, error) {
	_, config, err := p.config(httpContext(ctx), c)
	if err != nil {
		return "", err
	}
	return config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}
func (p Provider) Verify(ctx context.Context, c federation.Connection, code, nonce, verifier string) (string, error) {
	ctx = httpContext(ctx)
	provider, config, err := p.config(ctx, c)
	if err != nil {
		return "", err
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", errx.Unauthorized("provider exchange rejected")
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errx.Unauthorized("provider ID token required")
	}
	verified, err := provider.Verifier(&oidc.Config{ClientID: c.Client}).Verify(ctx, raw)
	if err != nil || verified.Nonce != nonce {
		return "", errx.Unauthorized("invalid provider identity")
	}
	return verified.Subject, nil
}

var _ federation.Provider = Provider{}
