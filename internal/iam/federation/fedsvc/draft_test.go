package fedsvc

import (
	"context"
	"crypto/sha256"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

const draftIssuer = "https://iam.example.com"

// counter hands out predictable secrets (federation.Secrets).
type counter struct{ n int }

func (c *counter) Generate(prefix string) (string, []byte, error) {
	c.n++
	raw := prefix + strconv.Itoa(c.n)
	return raw, c.Hash(raw), nil
}
func (c *counter) Hash(raw string) []byte { h := sha256.Sum256([]byte(raw)); return h[:] }

// metadataProvider is a federation.Provider that completes SAML metadata
// like fedsaml does, and fails a draft without any (it must never be asked).
type metadataProvider struct {
	federation.Provider
	prepared int
	claims   federation.Claims
	verify   error
}

func (p *metadataProvider) Prepare(_ context.Context, c federation.Connection) (federation.Connection, error) {
	p.prepared++
	if c.Options.MetadataURL == "" && c.Options.MetadataXML == "" {
		return c, errx.Validation("no metadata")
	}
	c.Options.MetadataXML = "<EntityDescriptor/>"
	c.Issuer = "https://idp.example.com/entity"
	c.Client = federation.SAMLServiceProvider(draftIssuer, c.Environment, c.ID).EntityID
	return c, nil
}
func (p *metadataProvider) Verifier() string { return "verifier" }
func (p *metadataProvider) Authorize(_ context.Context, _ federation.Connection, state, _, _ string) (string, error) {
	return "https://idp.example.com/authorize?state=" + state, nil
}
func (p *metadataProvider) Verify(context.Context, federation.Connection, string, string, string) (federation.Claims, error) {
	return p.claims, p.verify
}

type ticket struct {
	environment identity.EnvironmentID
	connection  identity.ConnectionID
	expires     time.Time
}

// memory is a federation.Repository over maps. Everything a test sign-in
// must not touch (users, links, sessions, provisioning) is left nil in the
// embedded interface, so touching it panics the test.
type memory struct {
	federation.Repository
	connections map[identity.ConnectionID]federation.Connection
	active      map[identity.ConnectionID]bool
	tickets     map[string]ticket
	states      map[string]federation.State
	created     []federation.Connection
	updated     []federation.Connection
	enabled     []federation.Connection
	recorded    []federation.TestResult
	finds       int
}

func newMemory() *memory {
	return &memory{connections: map[identity.ConnectionID]federation.Connection{}, active: map[identity.ConnectionID]bool{}, tickets: map[string]ticket{}, states: map[string]federation.State{}}
}

func (m *memory) Create(_ context.Context, _ federation.Mutation, c federation.Connection) error {
	m.connections[c.ID] = c
	m.active[c.ID] = !c.Draft
	m.created = append(m.created, c)
	return nil
}
func (m *memory) Update(_ context.Context, _ federation.Mutation, c federation.Connection) error {
	m.connections[c.ID] = c
	m.updated = append(m.updated, c)
	return nil
}
func (m *memory) Find(_ context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, error) {
	m.finds++
	if c, ok := m.connections[id]; ok && c.Environment == environment && m.active[id] {
		return c, nil
	}
	return federation.Connection{}, errx.NotFound("resource not found")
}
func (m *memory) FindAny(_ context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, error) {
	if c, ok := m.connections[id]; ok && c.Environment == environment {
		return c, nil
	}
	return federation.Connection{}, errx.NotFound("resource not found")
}
func (m *memory) FindDisabled(ctx context.Context, environment identity.EnvironmentID, id identity.ConnectionID) (federation.Connection, error) {
	c, err := m.FindAny(ctx, environment, id)
	if err != nil || m.active[id] {
		return federation.Connection{}, errx.NotFound("resource not found")
	}
	return c, nil
}
func (m *memory) Enable(_ context.Context, _ federation.Mutation, c federation.Connection) error {
	m.active[c.ID] = true
	m.connections[c.ID] = c
	m.enabled = append(m.enabled, c)
	return nil
}
func (m *memory) SaveTest(_ context.Context, mut federation.Mutation, hash []byte, id identity.ConnectionID, expires time.Time) error {
	m.tickets[string(hash)] = ticket{environment: mut.Environment, connection: id, expires: expires}
	return nil
}
func (m *memory) UseTest(_ context.Context, hash []byte, environment identity.EnvironmentID, id identity.ConnectionID) (string, error) {
	t, ok := m.tickets[string(hash)]
	if !ok || t.environment != environment || t.connection != id || t.expires.Before(time.Now()) {
		return "", errx.Unauthorized("invalid or expired test connection link")
	}
	delete(m.tickets, string(hash)) // spent by a match, like the SQL UPDATE
	return "operator", nil
}
func (m *memory) RecordTest(_ context.Context, r federation.TestResult, _ string) error {
	m.recorded = append(m.recorded, r)
	return nil
}
func (m *memory) SaveState(_ context.Context, hash []byte, s federation.State) error {
	m.states[string(hash)] = s
	return nil
}
func (m *memory) ConsumeState(_ context.Context, hash, binding []byte) (federation.State, error) {
	s, ok := m.states[string(hash)]
	delete(m.states, string(hash))
	if !ok || string(s.Binding) != string(binding) {
		return federation.State{}, errx.Unauthorized("invalid federation callback")
	}
	return s, nil
}

func draftSetup(t *testing.T) (*Service, *memory, *metadataProvider, federation.Mutation, *counter) {
	t.Helper()
	r, p, secrets := newMemory(), &metadataProvider{}, &counter{}
	s := New(r, p, nil, nil, secrets, nil, draftIssuer)
	return s, r, p, federation.Mutation{Environment: identity.NewEnvironmentID(), Actor: "operator", Action: "create", Target: "/federation-connections"}, secrets
}

func createDraft(t *testing.T, s *Service, m federation.Mutation) identity.ConnectionID {
	t.Helper()
	id, err := s.Create(context.Background(), m, federation.ConnectionInput{Organization: identity.NewOrganizationID(), Name: "Okta", Provider: federation.ProviderSAML, Draft: true})
	if err != nil {
		t.Fatalf("create draft: %v", err)
	}
	return id
}

func TestDraftCreatePatchEnable(t *testing.T) {
	ctx := context.Background()
	s, r, p, m, _ := draftSetup(t)
	id := createDraft(t, s, m)
	if p.prepared != 0 {
		t.Fatalf("a draft without metadata asked the provider to prepare it %d times", p.prepared)
	}
	c := r.created[0]
	entity := federation.SAMLServiceProvider(draftIssuer, m.Environment, id).EntityID
	if !c.Draft || r.active[id] || c.Issuer != entity || c.Client != entity {
		t.Fatalf("stored draft: %+v", c)
	}
	// SP values are available at once.
	detail := federation.ConnectionDetail{}
	detail.SAML = &federation.ServiceProvider{}
	if sp := federation.SAMLServiceProvider(draftIssuer, m.Environment, id); sp.ACS == "" || sp.Metadata == "" || sp.EntityID == "" {
		t.Fatalf("service provider values: %+v", sp)
	}
	// It cannot go live without metadata.
	if err := s.Enable(ctx, m, id); err == nil {
		t.Fatal("a draft without metadata was enabled")
	}
	if len(r.enabled) != 0 {
		t.Fatal("enabled without metadata")
	}
	// The metadata arrives by PATCH: the connection stays a draft.
	url := "https://idp.example.com/metadata"
	if err := s.Update(ctx, m, id, federation.ConnectionUpdate{Options: &federation.Options{MetadataURL: url}}); err != nil {
		t.Fatalf("patch: %v", err)
	}
	u := r.updated[0]
	if !u.Draft || r.active[id] || u.Issuer != "https://idp.example.com/entity" || u.Options.MetadataURL != url {
		t.Fatalf("patched draft: %+v", u)
	}
	// Enabling prepares the metadata again and clears the draft flag.
	prepared := p.prepared
	if err := s.Enable(ctx, m, id); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if p.prepared != prepared+1 || len(r.enabled) != 1 || r.enabled[0].Draft || !r.active[id] {
		t.Fatalf("enabled: prepared=%d %+v", p.prepared, r.enabled)
	}
}

func TestDraftCreateRefusals(t *testing.T) {
	s, _, _, m, _ := draftSetup(t)
	org := identity.NewOrganizationID()
	for name, in := range map[string]federation.ConnectionInput{
		"with metadata": {Organization: org, Name: "x", Provider: federation.ProviderSAML, Draft: true, Options: federation.Options{MetadataURL: "https://idp.example.com/m"}},
		"oidc":          {Organization: org, Name: "x", Provider: federation.ProviderOIDC, Draft: true, Issuer: "https://idp", Client: "c", ClientSecret: "s"},
	} {
		if _, err := s.Create(context.Background(), m, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	plain := New(newMemory(), &metadataProvider{}, nil, nil, &counter{}, nil, "http://iam.example.com")
	if _, err := plain.Create(context.Background(), m, federation.ConnectionInput{Organization: org, Name: "x", Provider: federation.ProviderSAML, Draft: true}); err == nil {
		t.Error("draft over http accepted")
	}
}

func ticketOf(t *testing.T, raw string) (identity.EnvironmentID, identity.ConnectionID, string) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/identity/v1/federation/test/"), "/")
	env, err := identity.ParseEnvironmentID(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	conn, err := identity.ParseConnectionID(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return env, conn, u.Query().Get("ticket")
}

// activeOIDC returns an active OIDC connection and a draft with metadata.
func activeOIDC(t *testing.T, r *memory, environment identity.EnvironmentID) federation.Connection {
	t.Helper()
	c := federation.Connection{ID: identity.NewConnectionID(), Environment: environment, Organization: identity.NewOrganizationID(), Name: "Okta OIDC", Provider: federation.ProviderOIDC}
	r.connections[c.ID] = c
	r.active[c.ID] = true
	return c
}

func TestTestTicketIsSingleUseBoundAndShortLived(t *testing.T) {
	ctx := context.Background()
	s, r, _, m, _ := draftSetup(t)
	c := activeOIDC(t, r, m.Environment)
	issued, err := s.IssueTest(ctx, m, c.ID)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.ExpiresAt.After(time.Now().Add(11*time.Minute)) || issued.ExpiresAt.Before(time.Now().Add(9*time.Minute)) {
		t.Fatalf("expires %v, want about 10 minutes", issued.ExpiresAt)
	}
	env, conn, raw := ticketOf(t, issued.URL)
	if !strings.HasPrefix(raw, federation.TestPrefix) || env != m.Environment || conn != c.ID {
		t.Fatalf("ticket %q env %v conn %v", raw, env, conn)
	}
	for _, stored := range r.tickets {
		if stored.connection != c.ID {
			t.Fatal("ticket stored for another connection")
		}
	}
	for k := range r.tickets {
		if strings.Contains(k, raw) {
			t.Fatal("the raw ticket is stored; only its hash may be")
		}
	}
	// Bound to the connection: another connection's URL does not work (the
	// ticket is only spent by its own connection).
	other := activeOIDC(t, r, m.Environment)
	if _, err = s.StartTest(ctx, m.Environment, other.ID, raw); err == nil {
		t.Fatal("ticket worked for another connection")
	}
	if _, err = s.StartTest(ctx, m.Environment, c.ID, raw); err != nil {
		t.Fatalf("the ticket of its own connection: %v", err)
	}
	// Single use.
	issued, _ = s.IssueTest(ctx, m, c.ID)
	_, _, raw = ticketOf(t, issued.URL)
	start, err := s.StartTest(ctx, m.Environment, c.ID, raw)
	if err != nil || start.URL == "" || start.Binding == "" {
		t.Fatalf("start: %+v %v", start, err)
	}
	if _, err = s.StartTest(ctx, m.Environment, c.ID, raw); err == nil {
		t.Fatal("ticket reused")
	}
	// Bound to the environment.
	issued, _ = s.IssueTest(ctx, m, c.ID)
	_, _, raw = ticketOf(t, issued.URL)
	if _, err = s.StartTest(ctx, identity.NewEnvironmentID(), c.ID, raw); err == nil {
		t.Fatal("ticket worked in another environment")
	}
	// Expiry.
	issued, _ = s.IssueTest(ctx, m, c.ID)
	_, _, raw = ticketOf(t, issued.URL)
	for k, v := range r.tickets {
		v.expires = time.Now().Add(-time.Second)
		r.tickets[k] = v
	}
	if _, err = s.StartTest(ctx, m.Environment, c.ID, raw); err == nil {
		t.Fatal("expired ticket worked")
	}
	// Not a ticket at all.
	for _, bad := range []string{"", "ik_state_1", federation.TestPrefix + strings.Repeat("a", 200)} {
		if _, err = s.StartTest(ctx, m.Environment, c.ID, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTestConnectionRefusals(t *testing.T) {
	ctx := context.Background()
	s, r, _, m, _ := draftSetup(t)
	ldap := federation.Connection{ID: identity.NewConnectionID(), Environment: m.Environment, Organization: identity.NewOrganizationID(), Provider: federation.ProviderLDAP}
	r.connections[ldap.ID] = ldap
	r.active[ldap.ID] = true
	if _, err := s.IssueTest(ctx, m, ldap.ID); err == nil || !strings.Contains(err.Error(), "LDAP") {
		t.Fatalf("LDAP: %v", err)
	}
	draft := createDraft(t, s, m)
	if _, err := s.IssueTest(ctx, m, draft); err == nil || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("draft without metadata: %v", err)
	}
	if _, err := s.IssueTest(ctx, m, identity.NewConnectionID()); err == nil {
		t.Fatal("unknown connection")
	}
	// A draft with metadata, and an inactive connection, can be tested.
	if err := s.Update(ctx, m, draft, federation.ConnectionUpdate{Options: &federation.Options{MetadataURL: "https://idp.example.com/metadata"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.IssueTest(ctx, m, draft); err != nil {
		t.Fatalf("draft with metadata: %v", err)
	}
	off := activeOIDC(t, r, m.Environment)
	r.active[off.ID] = false
	if _, err := s.IssueTest(ctx, m, off.ID); err != nil {
		t.Fatalf("inactive connection: %v", err)
	}
}

func startTest(t *testing.T, s *Service, m federation.Mutation, id identity.ConnectionID) (state, binding string) {
	t.Helper()
	issued, err := s.IssueTest(context.Background(), m, id)
	if err != nil {
		t.Fatal(err)
	}
	_, _, raw := ticketOf(t, issued.URL)
	start, err := s.StartTest(context.Background(), m.Environment, id, raw)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("state"), start.Binding
}

func TestTestCallbackReportsAndCreatesNothing(t *testing.T) {
	ctx := context.Background()
	s, r, p, m, _ := draftSetup(t)
	c := activeOIDC(t, r, m.Environment)
	verified := true
	p.claims = federation.Claims{Subject: "u-1", Email: "ana@example.com", EmailVerified: &verified, Name: "Ana", Groups: []string{"eng", "ops"}}
	state, binding := startTest(t, s, m, c.ID)
	// s.sessions, s.actions, s.quota and every account method of the
	// repository are nil: the callback panics if it tries a sign-in.
	out, err := s.Callback(ctx, "code", state, binding)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if out.Test == nil || !out.Test.Success || out.Test.Email != "ana@example.com" || out.Test.Subject != "u-1" || out.Test.DisplayName != "Ana" || len(out.Test.Groups) != 2 || out.Test.EmailVerified != "true" {
		t.Fatalf("result: %+v", out.Test)
	}
	if !out.Issued.User.IsZero() || !out.Issued.Session.IsZero() || out.Issued.Refresh != "" || out.MFA != nil || out.Continuation != "" || out.ReturnTo != "" || out.Result != "" {
		t.Fatalf("a test callback returned sign-in state: %+v", out)
	}
	if len(r.recorded) != 1 || !r.recorded[0].Success || r.finds != 0 {
		t.Fatalf("recorded=%d finds=%d", len(r.recorded), r.finds)
	}
	// The state is single use.
	if _, err = s.Callback(ctx, "code", state, binding); err == nil {
		t.Fatal("state reused")
	}
	// A failure is part of the result, not an error.
	p.verify = errx.Unauthorized("the ID token has the wrong audience")
	state, binding = startTest(t, s, m, c.ID)
	out, err = s.Callback(ctx, "code", state, binding)
	if err != nil || out.Test == nil || out.Test.Success || !strings.Contains(out.Test.Error, "audience") || out.Test.Email != "" {
		t.Fatalf("failed result: %+v %v", out.Test, err)
	}
	if len(r.recorded) != 2 || r.recorded[1].Success {
		t.Fatalf("recorded: %+v", r.recorded)
	}
	// An internal failure never leaks its text into the page.
	p.verify = errx.Wrap(context.DeadlineExceeded, "dial 10.0.0.1:443 with secret", errx.TypeInternal)
	state, binding = startTest(t, s, m, c.ID)
	out, _ = s.Callback(ctx, "code", state, binding)
	if out.Test == nil || strings.Contains(out.Test.Error, "10.0.0.1") || strings.Contains(out.Test.Error, "secret") {
		t.Fatalf("internal error leaked: %+v", out.Test)
	}
}
