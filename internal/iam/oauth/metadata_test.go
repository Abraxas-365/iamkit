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
		"https://xn--bcher-kva.example/client.json",
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
		"https://claude.ai./a",
		"https://CLAUDE.AI/a",
		"https://bücher.example/a",
		"https://-claude.ai/a",
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
	// A native app's reverse-DNS private-use scheme (RFC 8252 §7.1).
	if _, err = (ClientMetadata{ClientID: claude.String(), RedirectURIs: []string{"com.example.app:/oauth2redirect"}}).Validate(claude); err != nil {
		t.Fatalf("private scheme: %v", err)
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
		"bare custom scheme":      {ClientID: claude.String(), RedirectURIs: []string{"cursor://cb"}},
		"javascript redirect":     {ClientID: claude.String(), RedirectURIs: []string{"javascript:alert(1)"}},
		"data redirect":           {ClientID: claude.String(), RedirectURIs: []string{"data:text/html,x"}},
		"long redirect":           {ClientID: claude.String(), RedirectURIs: []string{"https://claude.ai/" + strings.Repeat("a", 260)}},
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
		// M-2: documents turned off at the server or the environment.
		{Client{Source: SourceCIMD, Admission: AdmissionApproved, Disabled: true}, false},
		{Client{Source: SourceCIMD, Admission: AdmissionApproved, AdmissionExpiresAt: &future, Disabled: true}, false},
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
		"https://CLAUDE.ai/oauth/x":                       true,
		"https://claude.ai./oauth/x":                      true,
		"https://claude.ai:8443/oauth/x":                  false,
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
	// One spelling per host: case, a trailing dot and IDNs are canonicalized.
	for in, want := range map[string]string{
		"https://Tools.Example":         "https://tools.example",
		"https://tools.example.":        "https://tools.example",
		"https://BÜCHER.example":        "https://xn--bcher-kva.example",
		"https://xn--bcher-kva.example": "https://xn--bcher-kva.example",
	} {
		got, err := AllowlistCreate{Origin: in, PathPrefix: "/"}.Resolve(false)
		if err != nil || got.Origin != want {
			t.Errorf("%q = %q, %v; want %q", in, got.Origin, err, want)
		}
	}
	for name, in := range map[string]AllowlistCreate{
		"http":       {Origin: "http://tools.example", PathPrefix: "/"},
		"path":       {Origin: "https://tools.example/x", PathPrefix: "/"},
		"port":       {Origin: "https://tools.example:8443", PathPrefix: "/"},
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

// The redirect URIs templates ship come from the vendors' documentation
// (see presets): a change here is a deliberate edit with a new source.
func TestPresetRedirects(t *testing.T) {
	for key, want := range map[string]string{
		"cursor":      "http://localhost:8787/callback https://www.cursor.com/agents/mcp/oauth/callback",
		"antigravity": "https://antigravity.google/oauth-callback",
		"gemini_cli":  "http://localhost/oauth/callback",
	} {
		p, ok := FindPreset(key)
		if !ok || strings.Join(p.Redirects, " ") != want || p.Network != NetworkLocal {
			t.Errorf("%s: %+v", key, p)
		}
	}
	if p, _ := FindPreset("gemini_cli"); !p.LoopbackAnyPort {
		t.Error("gemini_cli listens on a random port")
	}
	if p, _ := FindPreset("cursor"); !strings.Contains(p.Notes, "internet") {
		t.Errorf("cursor must warn that the web callback needs public reachability: %q", p.Notes)
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
			if p.MetadataURL != "" || len(p.Redirects) == 0 || ValidateClientShape(DefaultGrantTypes, true, p.Redirects) != nil || identity.ValidateClientRedirects(p.Redirects) != nil {
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
	if (Approval{MetadataHash: "h"}).Validate(now) != nil || (Approval{MetadataHash: "h", ExpiresAt: &future}).Validate(now) != nil || (Approval{MetadataHash: "h", ExpiresAt: &past}).Validate(now) == nil {
		t.Fatal("approval expiry")
	}
	if (Approval{}).Validate(now) == nil || (Approval{MetadataHash: " "}).Validate(now) == nil {
		t.Fatal("approval without the reviewed metadata_hash")
	}
	if (ExternalClientFilter{Admission: "x"}).Validate() == nil || (ExternalClientFilter{Admission: AdmissionPending}).Validate() != nil {
		t.Fatal("filter")
	}
}

func TestMetadataHash(t *testing.T) {
	base := MetadataHash([]string{"https://a.example/cb", "http://localhost/cb"}, "", "none")
	if base != MetadataHash([]string{"http://localhost/cb", "https://a.example/cb"}, "", "none") {
		t.Fatal("redirect order must not matter")
	}
	for name, other := range map[string]string{
		"redirect added": MetadataHash([]string{"https://a.example/cb", "http://localhost/cb", "https://evil.example/cb"}, "", "none"),
		"redirect moved": MetadataHash([]string{"https://a.example/cb", "http://localhost/other"}, "", "none"),
		"jwks_uri":       MetadataHash([]string{"https://a.example/cb", "http://localhost/cb"}, "https://a.example/jwks", "none"),
		"method":         MetadataHash([]string{"https://a.example/cb", "http://localhost/cb"}, "", "private_key_jwt"),
	} {
		if other == base {
			t.Errorf("%s did not change the hash", name)
		}
	}
	// Fields are delimited: moving a character across them differs.
	if MetadataHash([]string{"a"}, "bc", "") == MetadataHash([]string{"ab"}, "c", "") {
		t.Fatal("ambiguous encoding")
	}
	doc := ExternalClient{Redirects: []string{"https://a.example/cb"}, Auth: identity.ClientAuth{Method: "none"}, Name: "A"}
	renamed := doc
	renamed.Name = "B"
	if doc.Hash() != renamed.Hash() {
		t.Fatal("a name is not vouched for")
	}
}

func TestAdmissionSource(t *testing.T) {
	u := mustURL(t, "https://claude.ai/oauth/claude-code-client-metadata")
	listed := ExternalTarget{ClientAdmission: ClientAdmissionAllowlist, Allowlist: []AllowlistEntry{{Origin: "https://claude.ai", PathPrefix: "/oauth/claude-code-client-metadata"}}}
	if got := listed.AdmissionSource(u.String()); got != SourceAllowlist {
		t.Fatalf("allowlist = %q", got)
	}
	listed.Allowlist[0].Preset = "claude_code"
	if got := listed.AdmissionSource(u.String()); got != SourcePreset {
		t.Fatalf("preset = %q", got)
	}
	if got := (ExternalTarget{ClientAdmission: ClientAdmissionOpen}).AdmissionSource(u.String()); got != SourceOpen {
		t.Fatalf("open = %q", got)
	}
	if got := (ExternalTarget{ClientAdmission: ClientAdmissionAllowlist}).AdmissionSource(u.String()); got != "" {
		t.Fatalf("unlisted = %q", got)
	}
	// A dynamically registered client_id names nothing an entry vouches
	// for, even an entry that matches everything: only an open server
	// admits it.
	dcr := "dcr_0123456789abcdef0123456789abcdef"
	everything := ExternalTarget{ClientAdmission: ClientAdmissionAllowlist, Allowlist: []AllowlistEntry{{Origin: "https://claude.ai", PathPrefix: "/"}}}
	if got := everything.AdmissionSource(dcr); got != "" {
		t.Fatalf("dcr on allowlist = %q", got)
	}
	if got := (ExternalTarget{ClientAdmission: ClientAdmissionOpen}).AdmissionSource(dcr); got != SourceOpen {
		t.Fatalf("dcr open = %q", got)
	}
	if (ExternalTarget{ClientAdmission: ClientAdmissionAllowlist}).Admission(dcr) != AdmissionPending {
		t.Fatal("dcr must wait on an allowlist server")
	}
}

func TestExternalTargetAllows(t *testing.T) {
	documents := ExternalTarget{AllowClientMetadata: true}
	if !documents.Allows(SourceCIMD) || documents.Allows(SourceDCR) {
		t.Fatal("documents only")
	}
	registered := ExternalTarget{AllowDynamicRegistration: true}
	if registered.Allows(SourceCIMD) || !registered.Allows(SourceDCR) {
		t.Fatal("registrations only")
	}
}

func TestAdmissionBacklog(t *testing.T) {
	var e *errx.Error
	if !errors.As(ErrAdmissionBacklog(), &e) || e.Code != "CLIENT_ADMISSION_BACKLOG" || e.HTTPStatus != 429 {
		t.Fatalf("backlog = %#v", e)
	}
}

// M-3: the per-user limit is its own code, 429, and a hosted-page refusal.
func TestAccessRequestLimit(t *testing.T) {
	var e *errx.Error
	if !errors.As(ErrAccessRequestLimit(), &e) || e.Code != CodeClientRequestLimit || e.HTTPStatus != 429 || e.Code == CodeClientBacklog {
		t.Fatalf("limit = %#v", e)
	}
	if !IsClientRefusal(ErrAccessRequestLimit()) || !IsClientRefusal(ErrAdmissionBacklog()) || IsClientRefusal(errx.Validation("x")) {
		t.Fatal("IsClientRefusal")
	}
}

// One canonicalizer: whatever spelling an allowlist entry is created with,
// it matches exactly the client_id URLs ParseClientIDURL accepts for that
// host, and ParseClientIDURL refuses every spelling that is not canonical.
func TestHostCanonicalizerAgrees(t *testing.T) {
	for _, tc := range []struct{ entry, canonical string }{
		{"https://Tools.Example", "tools.example"},
		{"https://tools.example.", "tools.example"},
		{"https://BÜCHER.example", "xn--bcher-kva.example"},
	} {
		created, err := AllowlistCreate{Origin: tc.entry, PathPrefix: "/"}.Resolve(false)
		if err != nil || created.Origin != "https://"+tc.canonical {
			t.Fatalf("%s: %q %v", tc.entry, created.Origin, err)
		}
		entry := AllowlistEntry{Origin: created.Origin, PathPrefix: created.PathPrefix}
		u, err := ParseClientIDURL("https://" + tc.canonical + "/c.json")
		if err != nil || !entry.Matches(u) {
			t.Fatalf("%s: canonical client_id not matched: %v", tc.canonical, err)
		}
		// The non-canonical spelling is not a client_id, but a URL that skipped
		// the parser still matches the same entry, never another.
		raw := strings.TrimPrefix(tc.entry, "https://")
		if raw != tc.canonical {
			if _, err := ParseClientIDURL("https://" + raw + "/c.json"); err == nil {
				t.Errorf("%q accepted as a client_id", raw)
			}
			skipped, _ := url.Parse("https://" + raw + "/c.json")
			if !entry.Matches(skipped) {
				t.Errorf("%q does not match its own entry", raw)
			}
		}
	}
}
