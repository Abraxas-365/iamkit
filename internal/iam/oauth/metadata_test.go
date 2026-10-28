package oauth

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestParseClientIDURL(t *testing.T) {
	for _, ok := range []string{
		"https://claude.ai/oauth/claude-code-client-metadata",
		"https://chatgpt.com/oauth/client.json",
		"https://vscode.dev/oauth/client-metadata.json",
		"https://a-b.example.com/x",
	} {
		if _, err := ParseClientIDURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"7f9c3a52-7c55-4c4f-9b21-0b4a4e4c2c11",
		"http://claude.ai/oauth/x",
		"https://claude.ai",
		"https://claude.ai/",
		"https://claude.ai/a?b=c",
		"https://claude.ai/a?",
		"https://claude.ai/a#f",
		"https://user@claude.ai/a",
		"https://claude.ai:8443/a",
		"https://claude.ai:443/a",
		"https://127.0.0.1/a",
		"https://[::1]/a",
		"https://localhost/a",
		"https://Claude.ai/a",
		"https://claude.ai/a/../b",
		"https://claude.ai/./b",
		"https://claude_ai.com/a",
		"https://claude.ai/" + strings.Repeat("a", 250),
	} {
		if _, err := ParseClientIDURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := ParseClientIDURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestClientMetadataValidate(t *testing.T) {
	chatgpt := mustURL(t, "https://chatgpt.com/oauth/client.json")
	claude := mustURL(t, "https://claude.ai/oauth/mcp-oauth-client-metadata")

	// The live documents (plan §14.1) are accepted and reduced.
	ext, err := ClientMetadata{ClientID: claude.String(), ClientName: "Claude", RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"}, GrantTypes: []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none"}.Validate(claude)
	if err != nil || !ext.Public() || ext.Auth.JWKSURI != "" || strings.Join(ext.GrantTypes, " ") != "authorization_code refresh_token" || ext.Name != "Claude" {
		t.Fatalf("claude: %+v %v", ext, err)
	}
	ext, err = ClientMetadata{ClientID: chatgpt.String(), RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, TokenEndpointAuthMethod: "private_key_jwt", SigningAlg: "RS256", JWKSURI: "https://chatgpt.com/oauth/jwks.json"}.Validate(chatgpt)
	if err != nil || ext.Public() || ext.Auth.Method != identity.AuthPrivateKeyJWT || ext.Auth.JWKSURI != "https://chatgpt.com/oauth/jwks.json" {
		t.Fatalf("chatgpt: %+v %v", ext, err)
	}
	// Defaults: none, RS256, code + refresh.
	ext, err = ClientMetadata{ClientID: claude.String(), RedirectURIs: []string{"http://127.0.0.1/callback", "http://localhost/callback"}}.Validate(claude)
	if err != nil || ext.Auth.Method != identity.AuthNone || ext.Auth.SigningAlg != "RS256" || len(ext.GrantTypes) != 2 {
		t.Fatalf("defaults: %+v %v", ext, err)
	}
	// Without refresh_token in grant_types there is no refresh.
	ext, _ = ClientMetadata{ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, GrantTypes: []string{"authorization_code"}}.Validate(claude)
	if strings.Join(ext.GrantTypes, " ") != "authorization_code" {
		t.Fatalf("grants = %v", ext.GrantTypes)
	}
	// Unsafe or unusable optional members are dropped, not fatal.
	ext, _ = ClientMetadata{ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, LogoURI: "javascript:alert(1)", ClientURI: "http://claude.ai"}.Validate(claude)
	if ext.LogoURI != "" || ext.ClientURI != "" {
		t.Fatalf("unsafe uris kept: %+v", ext)
	}

	for name, m := range map[string]ClientMetadata{
		"other client_id":         {ClientID: "https://claude.ai/other", RedirectURIs: []string{"https://claude.ai/cb"}},
		"no redirects":            {ClientID: claude.String()},
		"too many redirects":      {ClientID: claude.String(), RedirectURIs: strings.Split(strings.Repeat("https://claude.ai/cb,", 11), ",")[:11]},
		"http redirect":           {ClientID: claude.String(), RedirectURIs: []string{"http://claude.ai/cb"}},
		"custom scheme":           {ClientID: claude.String(), RedirectURIs: []string{"cursor://cb"}},
		"fragment redirect":       {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb#x"}},
		"secret method":           {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, TokenEndpointAuthMethod: "client_secret_basic"},
		"client secret":           {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, ClientSecret: "x"},
		"inline jwks":             {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, TokenEndpointAuthMethod: "private_key_jwt", JWKS: map[string]any{"keys": []any{}}},
		"jwks_uri missing":        {ClientID: chatgpt.String(), RedirectURIs: []string{"https://chatgpt.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt"},
		"jwks_uri other origin":   {ClientID: chatgpt.String(), RedirectURIs: []string{"https://chatgpt.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt", JWKSURI: "https://keys.example/jwks.json"},
		"jwks_uri subdomain":      {ClientID: chatgpt.String(), RedirectURIs: []string{"https://chatgpt.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt", JWKSURI: "https://cdn.chatgpt.com/jwks.json"},
		"jwks_uri http":           {ClientID: chatgpt.String(), RedirectURIs: []string{"https://chatgpt.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt", JWKSURI: "http://chatgpt.com/jwks.json"},
		"symmetric alg":           {ClientID: chatgpt.String(), RedirectURIs: []string{"https://chatgpt.com/cb"}, TokenEndpointAuthMethod: "private_key_jwt", JWKSURI: "https://chatgpt.com/jwks.json", SigningAlg: "HS256"},
		"no authorization_code":   {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, GrantTypes: []string{"client_credentials"}},
		"no code response":        {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, ResponseTypes: []string{"token"}},
		"long name":               {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, ClientName: strings.Repeat("n", 101)},
		"control chars in name":   {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, ClientName: "a\nb"},
		"userinfo in redirect":    {ClientID: claude.String(), RedirectURIs: []string{"https://u@claude.ai/cb"}},
		"relative redirect":       {ClientID: claude.String(), RedirectURIs: []string{"/cb"}},
		"secret expiry announced": {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/cb"}, ClientSecretExpiresAt: 0},
	} {
		if _, err := m.Validate(m.clientIDOr(claude)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// clientIDOr is the URL a test document is validated against: its own
// client_id's host family, else fallback.
func (m ClientMetadata) clientIDOr(fallback *url.URL) *url.URL {
	if strings.HasPrefix(m.ClientID, "https://chatgpt.com/") {
		u, _ := url.Parse("https://chatgpt.com/oauth/client.json")
		return u
	}
	return fallback
}

func TestParseClientMetadata(t *testing.T) {
	if _, err := ParseClientMetadata([]byte("[1]")); err == nil {
		t.Fatal("array accepted")
	}
	m, err := ParseClientMetadata([]byte(`{"client_id":"https://x.example/a","redirect_uris":["https://x.example/cb"],"unknown":1}`))
	if err != nil || m.ClientID != "https://x.example/a" {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestDelegable(t *testing.T) {
	if err := (Client{}).Delegable(); err != nil {
		t.Fatal(err)
	}
	if err := (Client{Source: SourceRegistered}).Delegable(); err != nil {
		t.Fatal(err)
	}
	err := (Client{Source: SourceCIMD}).Delegable()
	var e *errx.Error
	if !errors.As(err, &e) || e.Code != CodeUnauthorizedClient {
		t.Fatalf("cimd client delegable: %v", err)
	}
}

func TestAdmitted(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Hour)
	for _, tc := range []struct {
		c    Client
		want bool
	}{
		{Client{}, true},
		{Client{Source: SourceRegistered}, true},
		{Client{Source: SourceCIMD, Admission: AdmissionApproved}, true},
		{Client{Source: SourceCIMD, Admission: AdmissionApproved, AdmissionExpiresAt: &future}, true},
		{Client{Source: SourceCIMD, Admission: AdmissionApproved, AdmissionExpiresAt: &past}, false},
		{Client{Source: SourceCIMD, Admission: AdmissionPending}, false},
		{Client{Source: SourceCIMD, Admission: AdmissionBlocked}, false},
	} {
		if got := tc.c.Admitted(now); got != tc.want {
			t.Errorf("%+v: %v", tc.c, got)
		}
	}
}

func TestPublicID(t *testing.T) {
	id := identity.NewClientID()
	if (Client{ID: id}).PublicID() != id.String() {
		t.Fatal("registered")
	}
	if (Client{ID: id, Source: SourceCIMD, ExternalID: "https://x.example/a"}).PublicID() != "https://x.example/a" {
		t.Fatal("external")
	}
}

func TestAllowlistMatches(t *testing.T) {
	e := AllowlistEntry{Origin: "https://claude.ai", PathPrefix: "/oauth"}
	for raw, want := range map[string]bool{
		"https://claude.ai/oauth":                         true,
		"https://claude.ai/oauth/claude-code-client-meta": true,
		"https://claude.ai/oauthx":                        false,
		"https://claude.ai/other":                         false,
		"https://evil.claude.ai/oauth/x":                  false,
		"https://claude.ai.evil.example/oauth/x":          false,
	} {
		u, _ := url.Parse(raw)
		if got := e.Matches(u); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
	exact := AllowlistEntry{Origin: "https://chatgpt.com", PathPrefix: "/oauth/client.json"}
	for raw, want := range map[string]bool{
		"https://chatgpt.com/oauth/client.json":       true,
		"https://chatgpt.com/oauth/client.jsonx":      false,
		"https://chatgpt.com/oauth/codex/client.json": false,
	} {
		u, _ := url.Parse(raw)
		if got := exact.Matches(u); got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
	root := AllowlistEntry{Origin: "https://tools.example", PathPrefix: "/"}
	if u, _ := url.Parse("https://tools.example/any/thing"); !root.Matches(u) {
		t.Error("root prefix")
	}
}

func TestInitialAdmission(t *testing.T) {
	u := mustURL(t, "https://claude.ai/oauth/claude-code-client-metadata")
	entries := []AllowlistEntry{{Origin: "https://chatgpt.com", PathPrefix: "/oauth/client.json"}}
	if InitialAdmission(ClientAdmissionAllowlist, entries, u) != AdmissionPending {
		t.Fatal("unlisted should wait")
	}
	if InitialAdmission(ClientAdmissionOpen, nil, u) != AdmissionApproved {
		t.Fatal("open")
	}
	entries = append(entries, AllowlistEntry{Origin: "https://claude.ai", PathPrefix: "/oauth/claude-code-client-metadata"})
	if InitialAdmission(ClientAdmissionAllowlist, entries, u) != AdmissionApproved {
		t.Fatal("listed")
	}
}

func TestAllowlistCreateResolve(t *testing.T) {
	got, err := AllowlistCreate{Preset: "chatgpt"}.Resolve(false)
	if err != nil || got.Origin != "https://chatgpt.com" || got.PathPrefix != "/oauth/client.json" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := (AllowlistCreate{Preset: "cursor"}).Resolve(true); err == nil {
		t.Fatal("template preset accepted in the allowlist")
	}
	if _, err := (AllowlistCreate{Preset: "nope"}).Resolve(true); err == nil {
		t.Fatal("unknown preset")
	}
	if _, err := (AllowlistCreate{Preset: "claude", Origin: "https://x.example"}).Resolve(true); err == nil {
		t.Fatal("preset with origin")
	}
	if _, err := (AllowlistCreate{Origin: "https://tools.example", PathPrefix: "/mcp"}).Resolve(false); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]AllowlistCreate{
		"http":       {Origin: "http://tools.example", PathPrefix: "/"},
		"path":       {Origin: "https://tools.example/x", PathPrefix: "/"},
		"port":       {Origin: "https://tools.example:8443", PathPrefix: "/"},
		"upper":      {Origin: "https://Tools.example", PathPrefix: "/"},
		"no slash":   {Origin: "https://tools.example", PathPrefix: "mcp"},
		"dot dot":    {Origin: "https://tools.example", PathPrefix: "/a/../b"},
		"query":      {Origin: "https://tools.example", PathPrefix: "/a?b"},
		"no origin":  {PathPrefix: "/"},
		"trailing /": {Origin: "https://tools.example/", PathPrefix: "/"},
	} {
		if _, err := in.Resolve(true); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestPresets(t *testing.T) {
	// D21: the one-click allowlist presets; D19: fixed-client templates;
	// D20: every preset says what network exposure it needs.
	want := map[string][2]string{
		"claude_code": {PresetMetadataDocument, NetworkLocal},
		"claude":      {PresetMetadataDocument, NetworkPublic},
		"chatgpt":     {PresetMetadataDocument, NetworkPublic},
		"codex":       {PresetMetadataDocument, NetworkLocal},
		"vscode":      {PresetMetadataDocument, NetworkLocal},
		"cursor":      {PresetTemplate, NetworkLocal},
		"antigravity": {PresetTemplate, NetworkLocal},
		"gemini_cli":  {PresetTemplate, NetworkLocal},
	}
	got := Presets(false)
	if len(got) != len(want) {
		t.Fatalf("presets = %d", len(got))
	}
	for _, p := range got {
		w, ok := want[p.Key]
		if !ok || p.Mechanism != w[0] || p.Network != w[1] || p.DevelopmentOnly {
			t.Errorf("%+v", p)
		}
		switch p.Mechanism {
		case PresetMetadataDocument:
			if _, err := ParseClientIDURL(p.MetadataURL); err != nil || len(p.Redirects) != 0 {
				t.Errorf("%s: %v", p.Key, err)
			}
		case PresetTemplate:
			if p.MetadataURL != "" || len(p.Redirects) == 0 || ValidateClientShape(DefaultGrantTypes, true, p.Redirects) != nil {
				t.Errorf("%s: bad template", p.Key)
			}
		}
	}
	if len(Presets(true)) != len(want)+1 {
		t.Fatal("inspector missing in development")
	}
	if p, ok := FindPreset("mcp_inspector"); !ok || !p.DevelopmentOnly {
		t.Fatal("inspector")
	}
	if p, _ := FindPreset("claude"); len(p.SourceRanges) != 1 || p.SourceRanges[0] != "160.79.104.0/21" {
		t.Fatalf("claude ranges %v", p.SourceRanges)
	}
	if p, _ := FindPreset("gemini_cli"); !p.LoopbackAnyPort {
		t.Fatal("gemini random port")
	}
	// Returned presets are copies.
	p, _ := FindPreset("cursor")
	p.Redirects[0] = "x"
	if q, _ := FindPreset("cursor"); q.Redirects[0] == "x" {
		t.Fatal("catalog mutated")
	}
}

func TestApprovalValidate(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Second), now.Add(time.Hour)
	if (Approval{}).Validate(now) != nil || (Approval{ExpiresAt: &future}).Validate(now) != nil || (Approval{ExpiresAt: &past}).Validate(now) == nil {
		t.Fatal("approval expiry")
	}
	if (ExternalClientFilter{Admission: "x"}).Validate() == nil || (ExternalClientFilter{Admission: AdmissionPending}).Validate() != nil {
		t.Fatal("filter")
	}
}
