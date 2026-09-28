package bootstrap

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedoidc"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// OperatorSSO is how operators sign in to the console: the settings, the
// client secret of each provider (by ID), and, for tests, the transport
// that reaches the providers (nil: the default transport, since the
// deployment's own identity provider may be on an internal network).
type OperatorSSO struct {
	Settings  management.SSOSettings
	Secrets   map[string]string
	Transport http.RoundTripper
}

// WithOperatorSSO configures operator sign-in; without it, operators sign
// in with a password only.
func WithOperatorSSO(c OperatorSSO) Option { return func(o *options) { o.sso = &c } }

const operatorSSOEnv = "IAMKIT_OPERATOR_SSO_"

// operatorSSOKeys are the settings of one provider,
// IAMKIT_OPERATOR_SSO_<ID>_<KEY>.
var operatorSSOKeys = []string{"TYPE", "NAME", "ISSUER", "CLIENT_ID", "CLIENT_SECRET", "CLIENT_SECRET_FILE", "ALLOWED_DOMAINS", "TENANT", "TENANTS"}

// operatorSSOFromEnv reads IAMKIT_OPERATOR_PASSWORD_LOGIN and the providers
// listed in IAMKIT_OPERATOR_SSO_PROVIDERS. Everything is checked now, so a
// typo stops the start; the providers themselves are only contacted at the
// first sign-in, so an outage never does.
func operatorSSOFromEnv() (OperatorSSO, error) {
	out := OperatorSSO{Secrets: map[string]string{}}
	mode, err := passwordModeFromEnv()
	if err != nil {
		return out, err
	}
	known := map[string]bool{operatorSSOEnv + "PROVIDERS": true}
	for _, id := range list(os.Getenv(operatorSSOEnv + "PROVIDERS")) {
		id = strings.ToLower(id)
		prefix := operatorSSOEnv + strings.ToUpper(strings.ReplaceAll(id, "-", "_")) + "_"
		for _, key := range operatorSSOKeys {
			known[prefix+key] = true
		}
		p, secret, err := operatorProviderFromEnv(id, prefix)
		if err != nil {
			return out, err
		}
		out.Settings.Providers = append(out.Settings.Providers, p)
		out.Secrets[id] = secret
	}
	// Unset: passwords for everyone without SSO; with SSO, only for the
	// operators an owner granted emergency access.
	out.Settings.Password = mode
	if mode == "" {
		out.Settings.Password = management.PasswordEnabled
		if len(out.Settings.Providers) > 0 {
			out.Settings.Password = management.PasswordBreakGlass
		}
	}
	if err := out.Settings.Validate(); err != nil {
		return out, err
	}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, operatorSSOEnv) && !known[name] {
			slog.Warn("ignored operator SSO setting: unknown name, or its provider is not in IAMKIT_OPERATOR_SSO_PROVIDERS", "name", name)
		}
	}
	if out.Settings.Password == management.PasswordDisabled && os.Getenv("IAMKIT_BOOTSTRAP_PASSWORD") != "" {
		slog.Warn("IAMKIT_BOOTSTRAP_PASSWORD is set but IAMKIT_OPERATOR_PASSWORD_LOGIN=disabled: the password cannot be used to sign in")
	}
	return out, nil
}

// passwordModeFromEnv reads IAMKIT_OPERATOR_PASSWORD_LOGIN: enabled,
// break_glass or disabled (true and false are enabled and disabled). Empty
// means unset: the default depends on whether SSO is configured.
func passwordModeFromEnv() (management.PasswordMode, error) {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("IAMKIT_OPERATOR_PASSWORD_LOGIN")))
	switch v {
	case "":
		return "", nil
	case string(management.PasswordEnabled), string(management.PasswordBreakGlass), string(management.PasswordDisabled):
		return management.PasswordMode(v), nil
	case "break-glass":
		return management.PasswordBreakGlass, nil
	}
	if enabled, err := strconv.ParseBool(v); err == nil {
		if enabled {
			return management.PasswordEnabled, nil
		}
		return management.PasswordDisabled, nil
	}
	return "", errx.Validation("IAMKIT_OPERATOR_PASSWORD_LOGIN must be enabled, break_glass or disabled")
}

func operatorProviderFromEnv(id, prefix string) (management.SSOProvider, string, error) {
	env := func(key string) string { return strings.TrimSpace(os.Getenv(prefix + key)) }
	p := management.SSOProvider{ID: id, Type: strings.ToLower(env("TYPE")), Name: env("NAME"), Issuer: env("ISSUER"), Client: env("CLIENT_ID"), Tenant: strings.ToLower(env("TENANT"))}
	if p.Type == "" {
		switch id {
		case management.SSOTypeOIDC, management.SSOTypeGoogle, management.SSOTypeMicrosoft, "github", "apple":
			p.Type = id
		default:
			return p, "", errx.Validation(prefix + "TYPE is required (oidc, google or microsoft)")
		}
	}
	if p.Name == "" {
		switch p.Type {
		case management.SSOTypeGoogle:
			p.Name = "Google"
		case management.SSOTypeMicrosoft:
			p.Name = "Microsoft"
		default:
			p.Name = strings.ToUpper(id[:1]) + id[1:]
		}
	}
	if p.Client == "" {
		return p, "", errx.Validation(prefix + "CLIENT_ID is required")
	}
	secret, file := os.Getenv(prefix+"CLIENT_SECRET"), env("CLIENT_SECRET_FILE")
	switch {
	case secret != "" && file != "":
		return p, "", errx.Validation("set one of " + prefix + "CLIENT_SECRET and " + prefix + "CLIENT_SECRET_FILE")
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return p, "", errx.Validation(prefix + "CLIENT_SECRET_FILE cannot be read")
		}
		secret = string(data)
	}
	if secret = strings.TrimSpace(secret); secret == "" {
		return p, "", errx.Validation(prefix + "CLIENT_SECRET or " + prefix + "CLIENT_SECRET_FILE is required")
	}
	for _, raw := range list(env("ALLOWED_DOMAINS")) {
		domain, err := identity.Domain(raw)
		if err != nil {
			return p, "", errx.Validation(prefix + "ALLOWED_DOMAINS: " + raw + " is not a domain such as example.com")
		}
		p.AllowedDomains = append(p.AllowedDomains, domain)
	}
	for _, t := range list(env("TENANTS")) {
		p.Tenants = append(p.Tenants, strings.ToLower(t))
	}
	if err := p.Validate(); err != nil {
		var e *errx.Error
		if errx.As(err, &e) {
			return p, "", errx.Validation(e.Message + " (" + prefix + "*)")
		}
		return p, "", err
	}
	return p, secret, nil
}

// list splits a comma-separated value, dropping blanks.
func list(raw string) []string {
	var out []string
	for _, v := range strings.Split(raw, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// operatorIdP signs operators in through the federation OIDC adapter: each
// configured provider becomes an in-memory connection with the deployment's
// secret and the console's own callback.
type operatorIdP struct {
	providers   map[string]fedoidc.Provider
	connections map[string]federation.Connection
}

var _ management.IdentityProvider = operatorIdP{}

// OperatorSSOCallback is the redirect URI to register at every operator
// identity provider.
func OperatorSSOCallback(issuer string) string { return issuer + "/management/v1/sso/callback" }

func newOperatorIdP(issuer string, c OperatorSSO) operatorIdP {
	out := operatorIdP{providers: map[string]fedoidc.Provider{}, connections: map[string]federation.Connection{}}
	for _, p := range c.Settings.Providers {
		o := federation.Options{Tenant: p.Tenant, Tenants: p.Tenants}
		if p.Type == management.SSOTypeGoogle {
			// fedoidc then refuses other hd claims too, independently of
			// SSOProvider.Admit.
			o.Domains = p.AllowedDomains
		}
		o = o.Normalized()
		conn := federation.Connection{Provider: p.Type, Issuer: p.Issuer, Client: p.Client, Options: o}
		if p.Type != management.SSOTypeOIDC {
			conn.Issuer = federation.Preset(p.Type, o)
		}
		out.connections[p.ID] = conn
		out.providers[p.ID] = fedoidc.Provider{Issuer: issuer, Transport: c.Transport, Redirect: OperatorSSOCallback(issuer), Secret: c.Secrets[p.ID]}
	}
	return out
}

func (i operatorIdP) lookup(id string) (fedoidc.Provider, federation.Connection, error) {
	p, ok := i.providers[id]
	if !ok {
		return p, federation.Connection{}, errx.NotFound("operator SSO provider not found")
	}
	return p, i.connections[id], nil
}

func (operatorIdP) Verifier() string { return fedoidc.Provider{}.Verifier() }

func (i operatorIdP) Authorize(ctx context.Context, provider, state, nonce, verifier string) (string, error) {
	p, c, err := i.lookup(provider)
	if err != nil {
		return "", err
	}
	return p.Authorize(ctx, c, state, nonce, verifier)
}

func (i operatorIdP) Verify(ctx context.Context, provider, code, nonce, verifier string) (management.SSOClaims, error) {
	p, c, err := i.lookup(provider)
	if err != nil {
		return management.SSOClaims{}, err
	}
	claims, err := p.Verify(ctx, c, code, nonce, verifier)
	if err != nil {
		return management.SSOClaims{}, err
	}
	return management.SSOClaims{Issuer: claims.Issuer, Subject: claims.Subject, Email: claims.Email, EmailVerified: claims.EmailVerified, Name: claims.Name, HostedDomain: claims.HostedDomain}, nil
}
