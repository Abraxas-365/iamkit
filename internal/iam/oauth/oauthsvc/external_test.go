package oauthsvc

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// fakeExternal is the external-client side of the repository; everything
// else stays nil (a call would panic, which a test would show).
type fakeExternal struct {
	oauth.Repository
	known    identity.ClientID
	saved    []oauth.ExternalSave
	unsaved  int
	requests []oauth.AccessRequest
	touched  []time.Duration
	pruned   int
	target   oauth.ExternalTarget
	// stored, when set, is the row FindExternal answers.
	stored *oauth.Client
	// registrations are the dynamic registrations Registration finds.
	registrations map[string]oauth.Registered
}

func (f *fakeExternal) Registration(_ context.Context, clientID string) (oauth.Registered, bool, error) {
	r, ok := f.registrations[clientID]
	return r, ok, nil
}

func (f *fakeExternal) ExternalTarget(context.Context, string) (oauth.ExternalTarget, error) {
	return f.target, nil
}
func (f *fakeExternal) ExternalTargetByID(context.Context, identity.ProtectedResourceID) (oauth.ExternalTarget, error) {
	return f.target, nil
}
func (f *fakeExternal) ExternalClientID(context.Context, identity.ProtectedResourceID, string) (identity.ClientID, error) {
	return f.known, nil
}
func (f *fakeExternal) UnsavedExternal(_ context.Context, target oauth.ExternalTarget, doc oauth.ExternalClient) (*oauth.Client, error) {
	f.unsaved++
	return &oauth.Client{Source: oauth.SourceCIMD, ExternalID: doc.ExternalID, Admission: oauth.AdmissionPending, Protected: &oauth.ProtectedTarget{ID: target.Protected}}, nil
}
func (f *fakeExternal) SaveExternalClient(_ context.Context, s oauth.ExternalSave) (identity.ClientID, error) {
	f.saved = append(f.saved, s)
	return s.ID, nil
}
func (f *fakeExternal) FindHolder(ctx context.Context, e identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	return f.FindExternal(ctx, e, id)
}
func (f *fakeExternal) FindActive(context.Context, identity.EnvironmentID, identity.ClientID) (*oauth.Client, error) {
	return nil, errx.NotFound("OAuth client not found")
}
func (f *fakeExternal) FindExternal(_ context.Context, _ identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	if f.stored != nil {
		return f.stored, nil
	}
	return &oauth.Client{ID: id, Source: oauth.SourceCIMD, Admission: oauth.AdmissionApproved}, nil
}
func (f *fakeExternal) RequestExternalAccess(_ context.Context, a oauth.AccessRequest) error {
	f.requests = append(f.requests, a)
	return nil
}
func (f *fakeExternal) TouchExternal(_ context.Context, _ identity.ClientID, interval time.Duration) error {
	f.touched = append(f.touched, interval)
	return nil
}
func (f *fakeExternal) PruneExternal(_ context.Context, before time.Time, limit int) (int, error) {
	if limit != config.ClientPendingPruneBatch || time.Since(before) < config.ClientPendingRetention-time.Minute {
		return 0, errors.New("wrong prune arguments")
	}
	return f.pruned, nil
}

type fakeDocuments struct {
	asked, reads int
	// fail, when set, is what a read answers (after admission).
	fail error
}

// Document reads once per call, admitting each like an uncached fetch.
func (d *fakeDocuments) Document(ctx context.Context, u *url.URL, admit oauth.Fetch) (oauth.ExternalClient, time.Time, error) {
	d.asked++
	if admit != nil {
		if err := admit(ctx); err != nil {
			return oauth.ExternalClient{}, time.Time{}, err
		}
	}
	d.reads++
	if d.fail != nil {
		return oauth.ExternalClient{}, time.Time{}, d.fail
	}
	return oauth.ExternalClient{ExternalID: u.String(), Name: "App", Redirects: []string{"http://localhost/cb"}, GrantTypes: []string{"authorization_code"}, Auth: identity.ClientAuth{Method: "none"}}, time.Now(), nil
}

type countingThrottle struct {
	max   int64
	taken map[string]int64
}

func (c *countingThrottle) Take(_ context.Context, key string, max int64, _ time.Duration) (bool, error) {
	c.taken[key]++
	return c.taken[key] <= max, nil
}

func newExternal(t *testing.T, target oauth.ExternalTarget) (*Service, *fakeExternal, *fakeDocuments, *countingThrottle) {
	t.Helper()
	repo := &fakeExternal{target: target}
	docs := &fakeDocuments{}
	throttle := &countingThrottle{taken: map[string]int64{}}
	s := New(repo, nil, nil, nil)
	s.SetExternalClients(docs, nil, throttle)
	return s, repo, docs, throttle
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// H1: a client nobody approved and no row holds is described, not written.
func TestResolveWritesNothingForUnapprovedClient(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: oauth.ClientAdmissionAllowlist}
	s, repo, _, _ := newExternal(t, target)
	client, err := s.resolve(context.Background(), target, "https://claude.ai/oauth/app")
	if err != nil || !client.ID.IsZero() || client.Admission != oauth.AdmissionPending {
		t.Fatalf("client = %+v, %v", client, err)
	}
	if len(repo.saved) != 0 || repo.unsaved != 1 {
		t.Fatalf("saved %d, unsaved %d", len(repo.saved), repo.unsaved)
	}
}

// Policy-approved clients are persisted at authorize, with their source.
func TestResolvePersistsApprovedByPolicy(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: oauth.ClientAdmissionOpen}
	s, repo, _, _ := newExternal(t, target)
	if _, err := s.resolve(context.Background(), target, "https://claude.ai/oauth/app"); err != nil {
		t.Fatal(err)
	}
	if len(repo.saved) != 1 || repo.saved[0].Admission != oauth.AdmissionApproved || repo.saved[0].Source != oauth.SourceOpen {
		t.Fatalf("saved = %+v", repo.saved)
	}
}

// A known pending row is refreshed (not described): it exists already.
func TestResolveRefreshesKnownRow(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: oauth.ClientAdmissionAllowlist}
	s, repo, _, _ := newExternal(t, target)
	repo.known = identity.NewClientID()
	if _, err := s.resolve(context.Background(), target, "https://claude.ai/oauth/app"); err != nil {
		t.Fatal(err)
	}
	if len(repo.saved) != 1 || repo.unsaved != 0 {
		t.Fatalf("saved %d, unsaved %d", len(repo.saved), repo.unsaved)
	}
}

// The environment's fetch budget: reads over it are 429, per environment;
// strangers (no row) use only config.ClientMetadataNewFetchesPerMinute of
// it, the rest is for known clients (M-4).
func TestFetchBudgetPerEnvironment(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: oauth.ClientAdmissionAllowlist}
	s, repo, docs, _ := newExternal(t, target)
	read := func(target oauth.ExternalTarget, i int) error {
		_, err := s.resolve(context.Background(), target, "https://claude.ai/oauth/app"+strconv.Itoa(i))
		return err
	}
	budget := func(err error) bool {
		var e *errx.Error
		return errors.As(err, &e) && e.HTTPStatus == 429 && e.Code == oauth.CodeFetchBudget
	}
	var refused int
	for i := range config.ClientMetadataFetchesPerMinute + 25 {
		if err := read(target, i); budget(err) {
			refused++
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if want := config.ClientMetadataFetchesPerMinute + 25 - config.ClientMetadataNewFetchesPerMinute; refused != want || docs.reads != config.ClientMetadataNewFetchesPerMinute {
		t.Fatalf("strangers: refused %d (want %d), reads %d", refused, want, docs.reads)
	}
	// Known clients still read: the reserved share.
	repo.known = identity.NewClientID()
	for i := range config.ClientMetadataFetchesPerMinute - config.ClientMetadataNewFetchesPerMinute {
		if err := read(target, 1000+i); err != nil {
			t.Fatalf("known client %d inside the reserved share: %v", i, err)
		}
	}
	if err := read(target, 2000); !budget(err) {
		t.Fatalf("known client past the environment's budget: %v", err)
	}
	other := target
	other.Environment = identity.NewEnvironmentID()
	if err := read(other, 3000); err != nil {
		t.Fatalf("another environment shares the budget: %v", err)
	}
}

// M-4: one address makes an environment read at most
// config.ClientMetadataFetchesPerIPPerMinute documents a minute; another
// address (and an IPv6 one's whole /64) is counted on its own.
func TestFetchBudgetPerAddress(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: oauth.ClientAdmissionAllowlist}
	s, _, docs, _ := newExternal(t, target)
	from := func(ip string, i int) error {
		ctx := identity.WithClientInfo(context.Background(), identity.NewClientInfo(ip, ""))
		_, err := s.resolve(ctx, target, "https://claude.ai/oauth/ip"+strconv.Itoa(i))
		return err
	}
	for i := range config.ClientMetadataFetchesPerIPPerMinute {
		if err := from("203.0.113.7", i); err != nil {
			t.Fatal(err)
		}
	}
	if err := from("203.0.113.7", 100); err == nil {
		t.Fatal("an address read past its budget")
	}
	if err := from("203.0.113.8", 101); err != nil {
		t.Fatalf("another address: %v", err)
	}
	for i := range config.ClientMetadataFetchesPerIPPerMinute {
		if err := from("2001:db8:1:2::"+strconv.Itoa(i+1), 200+i); err != nil {
			t.Fatal(err)
		}
	}
	if err := from("2001:db8:1:2:ffff::1", 300); err == nil {
		t.Fatal("a /64 read past one address's budget")
	}
	if docs.reads != 2*config.ClientMetadataFetchesPerIPPerMinute+1 {
		t.Fatalf("reads = %d", docs.reads)
	}
}

// M-4: an approved client whose document cannot be read now keeps its
// stored metadata for a bounded time; nothing else does.
func TestStaleIfError(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: oauth.ClientAdmissionAllowlist}
	s, repo, docs, _ := newExternal(t, target)
	repo.known = identity.NewClientID()
	u := mustParse(t, "https://claude.ai/oauth/stale")
	stored := func(adm string, age time.Duration) {
		repo.stored = &oauth.Client{ID: repo.known, Source: oauth.SourceCIMD, ExternalID: u.String(), Admission: adm, MetadataFetched: time.Now().Add(-age)}
	}
	for name, failure := range map[string]error{"unavailable": oauth.ErrDocumentUnavailable("host down"), "budget": oauth.ErrFetchBudget()} {
		docs.fail = failure
		stored(oauth.AdmissionApproved, config.ClientMetadataMaxTTL)
		c, err := s.resolve(context.Background(), target, u.String())
		if err != nil || c == nil || c.ID != repo.known {
			t.Fatalf("%s: stored metadata not served: %v", name, err)
		}
		if len(repo.saved) != 0 {
			t.Fatalf("%s: stored metadata was rewritten", name)
		}
	}
	docs.fail = oauth.ErrDocumentUnavailable("host down")
	stored(oauth.AdmissionApproved, config.ClientMetadataMaxTTL+config.ClientMetadataStaleFor+time.Minute)
	if _, err := s.resolve(context.Background(), target, u.String()); err == nil {
		t.Fatal("served past the staleness bound")
	}
	stored(oauth.AdmissionPending, time.Hour)
	if _, err := s.resolve(context.Background(), target, u.String()); err == nil {
		t.Fatal("a pending client was served from storage")
	}
	// The document is wrong, not unreachable: it stands.
	docs.fail = errx.Validation("redirect_uris is required")
	stored(oauth.AdmissionApproved, time.Hour)
	if _, err := s.resolve(context.Background(), target, u.String()); err == nil {
		t.Fatal("an invalid document was replaced by storage")
	}
	// A client with no row has nothing to serve.
	docs.fail = oauth.ErrDocumentUnavailable("host down")
	repo.known = identity.ClientID{}
	if _, err := s.resolve(context.Background(), target, u.String()); err == nil {
		t.Fatal("served a client with no row")
	}
}

func TestRequestAccessCarriesPolicy(t *testing.T) {
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID()}
	s, repo, _, _ := newExternal(t, target)
	s.SetPendingCap(3)
	client := &oauth.Client{Source: oauth.SourceCIMD, ExternalID: "https://claude.ai/oauth/app", Protected: &oauth.ProtectedTarget{ID: target.Protected}}
	user := identity.NewUserID()
	if err := s.RequestAccess(context.Background(), client, user, identity.OrganizationID{}); err != nil {
		t.Fatal(err)
	}
	if len(repo.requests) != 1 {
		t.Fatalf("requests = %d", len(repo.requests))
	}
	got := repo.requests[0]
	if got.MaxPending != 3 || got.Interval != config.ClientAccessRequestInterval || got.User != user || got.ID.IsZero() || got.Document.ExternalID != client.ExternalID {
		t.Fatalf("request = %+v", got)
	}
	// Blocked and registered clients never ask.
	client.Admission = oauth.AdmissionBlocked
	if err := s.RequestAccess(context.Background(), client, user, identity.OrganizationID{}); err != nil || len(repo.requests) != 1 {
		t.Fatalf("blocked asked: %v %d", err, len(repo.requests))
	}
}

func TestUsedTouchesExternalClientsOnly(t *testing.T) {
	s, repo, _, _ := newExternal(t, oauth.ExternalTarget{})
	ctx := context.Background()
	s.Used(ctx, &oauth.Client{ID: identity.NewClientID()})
	s.Used(ctx, &oauth.Client{Source: oauth.SourceCIMD})
	if len(repo.touched) != 0 {
		t.Fatalf("touched %v", repo.touched)
	}
	s.Used(ctx, &oauth.Client{ID: identity.NewClientID(), Source: oauth.SourceCIMD})
	if len(repo.touched) != 1 || repo.touched[0] != config.ClientUsedInterval {
		t.Fatalf("touched %v", repo.touched)
	}
}

func TestPruneExternalReportsMore(t *testing.T) {
	s, repo, _, _ := newExternal(t, oauth.ExternalTarget{})
	repo.pruned = config.ClientPendingPruneBatch
	if more, err := s.PruneExternal(context.Background()); err != nil || !more {
		t.Fatalf("full batch: %v %v", more, err)
	}
	repo.pruned = 3
	if more, err := s.PruneExternal(context.Background()); err != nil || more {
		t.Fatalf("short batch: %v %v", more, err)
	}
}

// flagsOn turns on the named features in every environment.
type flagsOn map[string]bool

func (f flagsOn) Enabled(_ context.Context, _ identity.EnvironmentID, name string) (bool, error) {
	return f[name], nil
}

const testDCR = "dcr_0123456789abcdef0123456789abcdef"

// A dynamically registered client is resolved from its registration (no
// fetch), refused unless the server and the environment take such clients,
// and, on an allowlist server, waits without a row.
func TestExternalClientDynamicRegistration(t *testing.T) {
	ctx := context.Background()
	resource := []string{"https://mcp.example/mcp"}
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), AllowClientMetadata: true, ClientAdmission: oauth.ClientAdmissionAllowlist}
	s, repo, docs, _ := newExternal(t, target)
	repo.registrations = map[string]oauth.Registered{testDCR: {ClientID: testDCR, Name: "Tool", Redirects: []string{"http://127.0.0.1/cb"}, GrantTypes: []string{"authorization_code"}, CreatedAt: time.Now()}}
	code := func(err error) string {
		var e *errx.Error
		if errors.As(err, &e) {
			return e.Code
		}
		return ""
	}
	// No feature service: dynamic registration is off.
	if _, err := s.ExternalClient(ctx, testDCR, resource); code(err) != oauth.CodeClientRegisteredOnly {
		t.Fatalf("server without dcr: %v", err)
	}
	repo.target.AllowDynamicRegistration = true
	if _, err := s.ExternalClient(ctx, testDCR, resource); code(err) != oauth.CodeClientRegisteredOnly {
		t.Fatalf("feature off: %v", err)
	}
	s.SetExternalClients(docs, flagsOn{config.FeatureDynamicClientRegistration: true}, nil)
	client, err := s.ExternalClient(ctx, testDCR, resource)
	if err != nil || client == nil || !client.ID.IsZero() || client.Admission != oauth.AdmissionPending {
		t.Fatalf("pending dcr client: %+v %v", client, err)
	}
	if docs.asked != 0 || len(repo.saved) != 0 || repo.unsaved != 1 {
		t.Fatalf("asked=%d saved=%d unsaved=%d", docs.asked, len(repo.saved), repo.unsaved)
	}
	// An unknown registration is an unknown client.
	if _, err := s.ExternalClient(ctx, "dcr_ffffffffffffffffffffffffffffffff", resource); err == nil || code(err) == oauth.CodeClientRegisteredOnly {
		t.Fatalf("unknown registration: %v", err)
	}
	// An open server admits it by policy and writes the row.
	repo.target.ClientAdmission = oauth.ClientAdmissionOpen
	if _, err := s.ExternalClient(ctx, testDCR, resource); err != nil || len(repo.saved) != 1 {
		t.Fatalf("open: %v saved=%d", err, len(repo.saved))
	}
	saved := repo.saved[0]
	if saved.Document.RowSource() != oauth.SourceDCR || saved.Admission != oauth.AdmissionApproved || saved.Source != oauth.SourceOpen {
		t.Fatalf("saved %+v", saved)
	}
	// Documents stay governed by their own flag.
	if _, err := s.ExternalClient(ctx, "https://claude.ai/oauth/app", resource); code(err) != oauth.CodeClientDisabled {
		t.Fatalf("document with its feature off: %v", err)
	}
}

type fakeRegistrations struct {
	saved     []oauth.Registered
	maxUnused int
	full      bool
	pruned    int
}

func (f *fakeRegistrations) SaveRegistration(_ context.Context, r oauth.Registered, maxUnused int) error {
	if f.full {
		return oauth.ErrRegistrationsFull()
	}
	f.saved = append(f.saved, r)
	f.maxUnused = maxUnused
	return nil
}

func (f *fakeRegistrations) PruneRegistrations(_ context.Context, unusedBefore, idleBefore time.Time, limit int) (int, error) {
	if limit != config.ClientRegistrationPruneBatch || time.Since(unusedBefore) < config.ClientRegistrationUnusedTTL-time.Minute || time.Since(idleBefore) < config.ClientRegistrationIdleTTL-time.Minute {
		return 0, errors.New("wrong prune arguments")
	}
	return f.pruned, nil
}

type fixedOffers oauth.Offers

func (f fixedOffers) Offered(context.Context) (oauth.Offers, error) { return oauth.Offers(f), nil }

func TestRegister(t *testing.T) {
	ctx := context.Background()
	input := oauth.ClientRegistration{RedirectURIs: []string{"http://127.0.0.1:33418/callback"}, ClientName: "Tool"}
	repo := &fakeRegistrations{}
	// Not offered anywhere: 404, nothing stored.
	for _, offers := range []oauth.Capabilities{nil, fixedOffers{ClientMetadataDocuments: true}} {
		if _, err := NewRegistrations(repo, offers).Register(ctx, input); err == nil || len(repo.saved) != 0 {
			t.Fatalf("registered while not offered: %v", err)
		}
	}
	s := NewRegistrations(repo, fixedOffers{DynamicRegistration: true})
	got, err := s.Register(ctx, input)
	if err != nil || !oauth.DynamicClientID(got.ClientID) || got.CreatedAt.IsZero() || len(repo.saved) != 1 || repo.maxUnused != config.ClientRegistrationMaxUnused {
		t.Fatalf("register: %+v %v", got, err)
	}
	if resp := got.Response(); resp.TokenEndpointAuthMethod != "none" || resp.ClientID != got.ClientID {
		t.Fatalf("response %+v", resp)
	}
	// Invalid metadata is refused before anything is stored.
	if _, err := s.Register(ctx, oauth.ClientRegistration{RedirectURIs: []string{"http://evil.example/cb"}}); err == nil || len(repo.saved) != 1 {
		t.Fatalf("invalid redirect: %v", err)
	}
	repo.full = true
	if _, err := s.Register(ctx, input); err == nil {
		t.Fatal("registered past the cap")
	}
	repo.pruned = config.ClientRegistrationPruneBatch
	if more, err := s.PruneRegistrations(ctx); err != nil || !more {
		t.Fatalf("prune: %v %v", more, err)
	}
}
