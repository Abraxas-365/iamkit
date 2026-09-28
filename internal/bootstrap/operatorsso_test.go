package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/management"
)

// clearOperatorSSOEnv unsets every operator SSO variable for the test.
func clearOperatorSSOEnv(t *testing.T) {
	t.Helper()
	t.Setenv("IAMKIT_OPERATOR_PASSWORD_LOGIN", "")
	t.Setenv("IAMKIT_BOOTSTRAP_PASSWORD", "")
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); strings.HasPrefix(name, operatorSSOEnv) {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
	}
}

func TestOperatorSSOFromEnvDefaults(t *testing.T) {
	clearOperatorSSOEnv(t)
	out, err := operatorSSOFromEnv()
	if err != nil || out.Settings.Password != management.PasswordEnabled || len(out.Settings.Providers) != 0 {
		t.Fatalf("defaults: %+v %v", out, err)
	}
	for _, v := range []string{"false", "disabled", "break_glass"} {
		t.Setenv("IAMKIT_OPERATOR_PASSWORD_LOGIN", v)
		if _, err = operatorSSOFromEnv(); err == nil {
			t.Fatalf("%s accepted without an SSO provider", v)
		}
	}
	t.Setenv("IAMKIT_OPERATOR_PASSWORD_LOGIN", "maybe")
	if _, err = operatorSSOFromEnv(); err == nil || !strings.Contains(err.Error(), "IAMKIT_OPERATOR_PASSWORD_LOGIN") {
		t.Fatalf("bad flag: %v", err)
	}
}

func TestPasswordModeFromEnv(t *testing.T) {
	for v, want := range map[string]management.PasswordMode{
		"": "", "true": management.PasswordEnabled, "1": management.PasswordEnabled, "Enabled": management.PasswordEnabled,
		"false": management.PasswordDisabled, "disabled": management.PasswordDisabled,
		"break_glass": management.PasswordBreakGlass, "BREAK-GLASS": management.PasswordBreakGlass,
	} {
		t.Setenv("IAMKIT_OPERATOR_PASSWORD_LOGIN", v)
		if got, err := passwordModeFromEnv(); err != nil || got != want {
			t.Errorf("%q: %q %v", v, got, err)
		}
	}
}

// TestOperatorSSOPasswordDefault: once a provider is configured and the
// mode is unset, passwords are for emergency access only.
func TestOperatorSSOPasswordDefault(t *testing.T) {
	clearOperatorSSOEnv(t)
	t.Setenv("IAMKIT_OPERATOR_SSO_PROVIDERS", "okta")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_TYPE", "oidc")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_ISSUER", "https://acme.okta.com")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_CLIENT_ID", "okta-client")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_CLIENT_SECRET", "okta-secret")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_ALLOWED_DOMAINS", "acme.com")
	out, err := operatorSSOFromEnv()
	if err != nil || out.Settings.Password != management.PasswordBreakGlass {
		t.Fatalf("default with SSO: %q %v", out.Settings.Password, err)
	}
	t.Setenv("IAMKIT_OPERATOR_PASSWORD_LOGIN", "true")
	if out, err = operatorSSOFromEnv(); err != nil || out.Settings.Password != management.PasswordEnabled {
		t.Fatalf("explicit enabled: %q %v", out.Settings.Password, err)
	}
}

func TestOperatorSSOFromEnvProviders(t *testing.T) {
	clearOperatorSSOEnv(t)
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IAMKIT_OPERATOR_PASSWORD_LOGIN", "false")
	t.Setenv("IAMKIT_OPERATOR_SSO_PROVIDERS", "okta, google ,entra")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_TYPE", "oidc")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_ISSUER", "https://acme.okta.com")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_CLIENT_ID", "okta-client")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_CLIENT_SECRET", "okta-secret")
	t.Setenv("IAMKIT_OPERATOR_SSO_OKTA_ALLOWED_DOMAINS", "acme.com")
	t.Setenv("IAMKIT_OPERATOR_SSO_GOOGLE_CLIENT_ID", "google-client")
	t.Setenv("IAMKIT_OPERATOR_SSO_GOOGLE_CLIENT_SECRET_FILE", secretFile)
	t.Setenv("IAMKIT_OPERATOR_SSO_GOOGLE_ALLOWED_DOMAINS", "Acme.com, acme.io")
	t.Setenv("IAMKIT_OPERATOR_SSO_ENTRA_TYPE", "microsoft")
	t.Setenv("IAMKIT_OPERATOR_SSO_ENTRA_NAME", "Acme Entra")
	t.Setenv("IAMKIT_OPERATOR_SSO_ENTRA_TENANT", "0b9b8c3e-5c1a-4f0e-9a4e-2d6f5b1c7a90")
	t.Setenv("IAMKIT_OPERATOR_SSO_ENTRA_CLIENT_ID", "entra-client")
	t.Setenv("IAMKIT_OPERATOR_SSO_ENTRA_CLIENT_SECRET", "entra-secret")
	t.Setenv("IAMKIT_OPERATOR_SSO_ENTRA_ALLOWED_DOMAINS", "acme.com")
	out, err := operatorSSOFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	s := out.Settings
	if s.Password != management.PasswordDisabled || len(s.Providers) != 3 || s.Providers[0].ID != "okta" || s.Providers[1].ID != "google" || s.Providers[2].ID != "entra" {
		t.Fatalf("settings %+v", s)
	}
	if g := s.Providers[1]; g.Type != management.SSOTypeGoogle || g.Name != "Google" || strings.Join(g.AllowedDomains, ",") != "acme.com,acme.io" {
		t.Fatalf("google %+v", g)
	}
	if s.Providers[2].Name != "Acme Entra" || s.Providers[0].Name != "Okta" {
		t.Fatalf("names %+v", s.Providers)
	}
	if out.Secrets["google"] != "file-secret" || out.Secrets["okta"] != "okta-secret" || out.Secrets["entra"] != "entra-secret" {
		t.Fatalf("secrets %v", out.Secrets)
	}

	idp := newOperatorIdP("https://iam.example", out)
	if c := idp.connections["entra"]; c.Issuer != "https://login.microsoftonline.com/0b9b8c3e-5c1a-4f0e-9a4e-2d6f5b1c7a90/v2.0" || c.Options.Domains != nil {
		t.Fatalf("entra connection %+v", c)
	}
	if c := idp.connections["google"]; c.Issuer != "https://accounts.google.com" || strings.Join(c.Options.Domains, ",") != "acme.com,acme.io" || !c.Options.AcceptsHostedDomain("acme.io") || c.Options.AcceptsHostedDomain("") {
		t.Fatalf("google connection %+v", c)
	}
	if p := idp.providers["okta"]; p.Redirect != "https://iam.example/management/v1/sso/callback" || p.Secret != "okta-secret" {
		t.Fatalf("okta provider %+v", p)
	}
	if _, _, err := idp.lookup("missing"); err == nil {
		t.Fatal("unknown provider found")
	}
}

func TestOperatorSSOFromEnvRejects(t *testing.T) {
	base := map[string]string{
		"IAMKIT_OPERATOR_SSO_PROVIDERS":              "idp",
		"IAMKIT_OPERATOR_SSO_IDP_TYPE":               "oidc",
		"IAMKIT_OPERATOR_SSO_IDP_ISSUER":             "https://idp.acme.com",
		"IAMKIT_OPERATOR_SSO_IDP_CLIENT_ID":          "client",
		"IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET":      "secret",
		"IAMKIT_OPERATOR_SSO_IDP_ALLOWED_DOMAINS":    "acme.com",
		"IAMKIT_OPERATOR_SSO_IDP_TENANT":             "",
		"IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET_FILE": "",
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no type", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_TYPE": ""}, "IAMKIT_OPERATOR_SSO_IDP_TYPE"},
		{"github", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_TYPE": "github"}, "IAMKIT_OPERATOR_SSO_IDP_"},
		{"no client", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_CLIENT_ID": ""}, "IAMKIT_OPERATOR_SSO_IDP_CLIENT_ID"},
		{"no secret", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET": ""}, "IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET"},
		{"two secrets", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET_FILE": "/x"}, "set one of"},
		{"missing file", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET": "", "IAMKIT_OPERATOR_SSO_IDP_CLIENT_SECRET_FILE": "/nonexistent/secret"}, "cannot be read"},
		{"http issuer", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_ISSUER": "http://idp.acme.com"}, "IAMKIT_OPERATOR_SSO_IDP_"},
		{"bad domain", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_ALLOWED_DOMAINS": "not a domain"}, "ALLOWED_DOMAINS"},
		{"microsoft common", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_TYPE": "microsoft", "IAMKIT_OPERATOR_SSO_IDP_ISSUER": "", "IAMKIT_OPERATOR_SSO_IDP_TENANT": "common"}, "IAMKIT_OPERATOR_SSO_IDP_"},
		{"google without domains", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_TYPE": "google", "IAMKIT_OPERATOR_SSO_IDP_ISSUER": "", "IAMKIT_OPERATOR_SSO_IDP_ALLOWED_DOMAINS": ""}, "allowed domains are required"},
		{"oidc without domains", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_ALLOWED_DOMAINS": " , "}, "allowed domains are required"},
		{"entra without domains", map[string]string{"IAMKIT_OPERATOR_SSO_IDP_TYPE": "microsoft", "IAMKIT_OPERATOR_SSO_IDP_ISSUER": "", "IAMKIT_OPERATOR_SSO_IDP_TENANT": "0b9b8c3e-5c1a-4f0e-9a4e-2d6f5b1c7a90", "IAMKIT_OPERATOR_SSO_IDP_ALLOWED_DOMAINS": ""}, "allowed domains are required"},
		{"duplicate", map[string]string{"IAMKIT_OPERATOR_SSO_PROVIDERS": "idp,IDP"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearOperatorSSOEnv(t)
			for k, v := range base {
				t.Setenv(k, v)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := operatorSSOFromEnv(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	clearOperatorSSOEnv(t)
	for k, v := range base {
		t.Setenv(k, v)
	}
	if _, err := operatorSSOFromEnv(); err != nil {
		t.Fatalf("base: %v", err)
	}
}
