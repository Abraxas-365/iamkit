package authsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/ptrx"
	"github.com/Abraxas-365/iamkit/internal/query"
)

func waitlistPolicy() authentication.SignInPolicy {
	p := signupPolicy()
	p.Waitlist = ptrx.Bool(true)
	p.WaitlistAutoApproveDomains = []string{"vip.example"}
	p.WaitlistSignupURL = ptrx.String("https://app.example.com/signup")
	return p
}

// approvedToken registers a live approval token for email in the store.
func approvedToken(store *signupStore, token, email string) identity.WaitlistEntryID {
	id := identity.NewWaitlistEntryID()
	store.tokens[token] = authentication.WaitlistToken{ID: id, Email: email}
	return id
}

// With the waitlist off nothing changes: a code is sent and the status is
// code_sent.
func TestSignupWaitlistOff(t *testing.T) {
	store := newSignupStore()
	delivery := &recordingDelivery{}
	s := signupService(store, signupPolicy(), delivery)
	out, err := s.Signup(context.Background(), signupInput())
	if err != nil || out.Status != authentication.SignupCodeSent || out.Challenge.IsZero() {
		t.Fatalf("%+v %v", out, err)
	}
	s.WaitDeliveries(time.Second)
	if len(delivery.got) != 1 || delivery.got[0].Purpose != authentication.PurposeEmailVerification || len(store.waitlist) != 0 {
		t.Fatalf("delivery %+v waitlist %v", delivery.got, store.waitlist)
	}
}

// With the waitlist on, an unapproved address joins: no code, a
// waitlist_joined email, status waitlisted.
func TestSignupWaitlisted(t *testing.T) {
	store := newSignupStore()
	delivery := &recordingDelivery{}
	s := signupService(store, waitlistPolicy(), delivery)
	out, err := s.Signup(context.Background(), signupInput())
	if err != nil || out.Status != authentication.SignupWaitlisted || out.Challenge.IsZero() {
		t.Fatalf("%+v %v", out, err)
	}
	s.WaitDeliveries(time.Second)
	entry := store.waitlist["new@example.com"]
	if entry == nil || entry.Status != authentication.WaitlistPending || entry.Name != " Ada " && entry.Name != "Ada" {
		t.Fatalf("entry: %+v", entry)
	}
	if len(store.pending) != 0 {
		t.Fatalf("a sign-up was parked: %v", store.pending)
	}
	if len(delivery.got) != 1 || delivery.got[0].Purpose != authentication.PurposeWaitlistJoined || delivery.got[0].Code != "" {
		t.Fatalf("delivery: %+v", delivery.got)
	}
}

// The answer is the same for a new address, one already waiting, one with
// an account and a full list; only a new entry sends the joined email.
func TestSignupWaitlistAntiEnumeration(t *testing.T) {
	shape := func(store *signupStore) (string, int) {
		delivery := &recordingDelivery{}
		s := signupService(store, waitlistPolicy(), delivery)
		out, err := s.Signup(context.Background(), signupInput())
		if err != nil || out.Challenge.IsZero() {
			t.Fatalf("%+v %v", out, err)
		}
		s.WaitDeliveries(time.Second)
		return out.Status, len(delivery.got)
	}
	fresh := newSignupStore()
	if status, sent := shape(fresh); status != authentication.SignupWaitlisted || sent != 1 {
		t.Fatalf("new: %s %d", status, sent)
	}
	waiting := newSignupStore()
	waiting.waitlist["new@example.com"] = &authentication.WaitlistEntry{Status: authentication.WaitlistPending}
	account := newSignupStore()
	account.exists = true
	full := newSignupStore()
	full.cap = true
	for name, store := range map[string]*signupStore{"waiting": waiting, "account": account, "full": full} {
		if status, sent := shape(store); status != authentication.SignupWaitlisted || sent != 0 {
			t.Fatalf("%s: %s sent=%d", name, status, sent)
		}
		if name != "waiting" && len(store.waitlist) != 0 {
			t.Fatalf("%s: entry created", name)
		}
	}
}

// An auto-approved domain skips the list; so does a valid token for the
// address, whose completion marks the entry.
func TestSignupWaitlistAutoApproveAndToken(t *testing.T) {
	store := newSignupStore()
	delivery := &recordingDelivery{}
	s := signupService(store, waitlistPolicy(), delivery)
	in := signupInput()
	in.Email = "ada@VIP.example"
	out, err := s.Signup(context.Background(), in)
	if err != nil || out.Status != authentication.SignupCodeSent || store.pending[out.Challenge] == nil && len(store.pending) != 0 {
		t.Fatalf("auto-approved: %+v %v", out, err)
	}

	entry := approvedToken(store, "ik_wait_good", "new@example.com")
	in = signupInput()
	in.WaitlistToken = "ik_wait_good"
	out, err = s.Signup(context.Background(), in)
	if err != nil || out.Status != authentication.SignupCodeSent {
		t.Fatalf("token: %+v %v", out, err)
	}
	if got := store.pending[out.Challenge]; got == nil || got.WaitlistEntry != entry {
		t.Fatalf("pending lost the entry: %+v", got)
	}
	if _, err = s.CompleteSignup(context.Background(), in.Environment, out.Challenge, "12345678"); err != nil {
		t.Fatal(err)
	}
	if len(store.completed) != 1 || store.completed[0] != entry {
		t.Fatalf("completed: %v", store.completed)
	}
}

// A token that is unknown, expired (the store no longer knows it) or for
// another address does not unlock the sign-up: it joins the list instead.
func TestSignupWaitlistBadToken(t *testing.T) {
	for name, token := range map[string]string{"unknown": "ik_wait_nope", "shape": "garbage", "other": "ik_wait_other"} {
		store := newSignupStore()
		approvedToken(store, "ik_wait_other", "someone@example.com")
		delivery := &recordingDelivery{}
		s := signupService(store, waitlistPolicy(), delivery)
		in := signupInput()
		in.WaitlistToken = token
		out, err := s.Signup(context.Background(), in)
		if err != nil || out.Status != authentication.SignupWaitlisted || len(store.pending) != 0 {
			t.Fatalf("%s: %+v %v pending=%d", name, out, err, len(store.pending))
		}
		if store.waitlist["new@example.com"] == nil && len(store.waitlist) != 0 {
			t.Fatalf("%s: wrong entry", name)
		}
	}
}

// A token is ignored when the waitlist is off.
func TestSignupWaitlistOffIgnoresToken(t *testing.T) {
	store := newSignupStore()
	s := signupService(store, signupPolicy(), &recordingDelivery{})
	in := signupInput()
	in.WaitlistToken = "ik_wait_nope"
	if out, err := s.Signup(context.Background(), in); err != nil || out.Status != authentication.SignupCodeSent {
		t.Fatalf("%+v %v", out, err)
	}
}

// denyRisk refuses every screen.
type denyRisk struct{}

func (denyRisk) Screen(context.Context, risk.Signal) error                  { return errx.Forbidden("blocked") }
func (denyRisk) Assess(context.Context, risk.Signal) risk.Decision          { return risk.Decision{} }
func (denyRisk) Record(context.Context, risk.Signal, string, risk.Decision) {}

// The risk screen still runs on join.
func TestSignupWaitlistScreened(t *testing.T) {
	store := newSignupStore()
	s := signupService(store, waitlistPolicy(), &recordingDelivery{})
	s.SetRisk(denyRisk{})
	if _, err := s.Signup(context.Background(), signupInput()); err == nil || len(store.waitlist) != 0 {
		t.Fatalf("screen skipped: %v", err)
	}
}

func TestWaitlistEmail(t *testing.T) {
	store := newSignupStore()
	s := signupService(store, waitlistPolicy(), &recordingDelivery{})
	approvedToken(store, "ik_wait_good", "new@example.com")
	env := testBoundary().EnvironmentID
	if email, err := s.WaitlistEmail(context.Background(), env, "ik_wait_good"); err != nil || email != "new@example.com" {
		t.Fatalf("%q %v", email, err)
	}
	for _, bad := range []string{"", "ik_wait_unknown", "nope"} {
		if _, err := s.WaitlistEmail(context.Background(), env, bad); code(err) != authentication.CodeWaitlistToken {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

// waitlistRepo is an in-memory WaitlistRepository.
type waitlistRepo struct {
	entries map[identity.WaitlistEntryID]*authentication.WaitlistEntry
	order   []identity.WaitlistEntryID
}

func newWaitlistRepo(emails ...string) *waitlistRepo {
	r := &waitlistRepo{entries: map[identity.WaitlistEntryID]*authentication.WaitlistEntry{}}
	for _, e := range emails {
		id := identity.NewWaitlistEntryID()
		r.entries[id] = &authentication.WaitlistEntry{ID: id, Email: e, Locale: "es", Status: authentication.WaitlistPending}
		r.order = append(r.order, id)
	}
	return r
}

func (r *waitlistRepo) ListWaitlist(_ context.Context, _ identity.EnvironmentID, f authentication.WaitlistFilter, page query.Pagination) (query.Paginated[authentication.WaitlistEntry], error) {
	var items []authentication.WaitlistEntry
	for _, id := range r.order {
		if e, ok := r.entries[id]; ok && (f.Status == "" || e.Status == f.Status) {
			items = append(items, *e)
		}
	}
	return query.NewPaginated(items, len(items), page), nil
}
func (r *waitlistRepo) FindWaitlist(_ context.Context, _ identity.EnvironmentID, id identity.WaitlistEntryID) (authentication.WaitlistEntry, error) {
	if e, ok := r.entries[id]; ok {
		return *e, nil
	}
	return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
}
func (r *waitlistRepo) PendingWaitlist(_ context.Context, _ identity.EnvironmentID, limit int) ([]authentication.WaitlistEntry, error) {
	var out []authentication.WaitlistEntry
	for _, id := range r.order {
		if e, ok := r.entries[id]; ok && e.Status == authentication.WaitlistPending && len(out) < limit {
			out = append(out, *e)
		}
	}
	return out, nil
}
func (r *waitlistRepo) ApproveWaitlist(_ context.Context, _ authentication.Mutation, a authentication.WaitlistApproval) (authentication.WaitlistEntry, error) {
	e, ok := r.entries[a.ID]
	if !ok {
		return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
	}
	if e.Status == authentication.WaitlistRejected || e.Status == authentication.WaitlistCompleted {
		return authentication.WaitlistEntry{}, authentication.ErrWaitlistNotDecidable()
	}
	e.Status, e.ExpiresAt = authentication.WaitlistApproved, &a.ExpiresAt
	return *e, nil
}
func (r *waitlistRepo) RejectWaitlist(_ context.Context, _ authentication.Mutation, id identity.WaitlistEntryID) (authentication.WaitlistEntry, error) {
	e, ok := r.entries[id]
	if !ok {
		return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
	}
	if e.Status == authentication.WaitlistRejected || e.Status == authentication.WaitlistCompleted {
		return authentication.WaitlistEntry{}, authentication.ErrWaitlistNotDecidable()
	}
	e.Status = authentication.WaitlistRejected
	return *e, nil
}
func (r *waitlistRepo) DeleteWaitlist(_ context.Context, _ authentication.Mutation, id identity.WaitlistEntryID) error {
	if _, ok := r.entries[id]; !ok {
		return errx.NotFound("waitlist entry not found")
	}
	delete(r.entries, id)
	return nil
}

// PruneWaitlist mirrors the SQL: completed or rejected entries decided
// (else created) before the cutoff, at most limit.
func (r *waitlistRepo) PruneWaitlist(_ context.Context, before time.Time, limit int) (int, error) {
	n := 0
	for id, e := range r.entries {
		if n == limit || (e.Status != authentication.WaitlistCompleted && e.Status != authentication.WaitlistRejected) {
			continue
		}
		at := e.CreatedAt
		if e.DecidedAt != nil {
			at = *e.DecidedAt
		}
		if at.Before(before) {
			delete(r.entries, id)
			n++
		}
	}
	return n, nil
}

// Prune keeps pending and approved entries and the recently decided ones,
// whatever their age.
func TestWaitlistPrune(t *testing.T) {
	repo := newWaitlistRepo("old-done@example.com", "old-rejected@example.com", "fresh-rejected@example.com", "old-pending@example.com", "old-approved@example.com")
	old, fresh := time.Now().Add(-config.WaitlistRetention-time.Hour), time.Now().Add(-time.Hour)
	set := func(i int, status string, at time.Time) {
		e := repo.entries[repo.order[i]]
		e.Status, e.CreatedAt, e.DecidedAt = status, at, &at
	}
	set(0, authentication.WaitlistCompleted, old)
	set(1, authentication.WaitlistRejected, old)
	set(2, authentication.WaitlistRejected, fresh)
	set(3, authentication.WaitlistPending, old)
	set(4, authentication.WaitlistApproved, old)
	w, _ := waitlistsFor(repo, &recordingDelivery{})
	if n, err := w.Prune(context.Background()); err != nil || n != 2 || len(repo.entries) != 3 {
		t.Fatalf("pruned %d (%v), left %d", n, err, len(repo.entries))
	}
	w.SetRetention(time.Minute)
	if n, err := w.Prune(context.Background()); err != nil || n != 1 || len(repo.entries) != 2 {
		t.Fatalf("shorter retention pruned %d (%v), left %d", n, err, len(repo.entries))
	}
}

func waitlistsFor(repo *waitlistRepo, delivery authentication.Delivery) (*Waitlists, *Service) {
	s := signupService(newSignupStore(), waitlistPolicy(), delivery)
	return NewWaitlists(repo, testSecrets{}, s), s
}

// Approving emails the sign-up link with the token; rejecting is silent
// unless notify; a rejected entry cannot be approved.
func TestWaitlistDecisions(t *testing.T) {
	repo := newWaitlistRepo("a@example.com", "b@example.com", "c@example.com")
	delivery := &recordingDelivery{}
	w, s := waitlistsFor(repo, delivery)
	m := authentication.Mutation{Environment: testBoundary().EnvironmentID, Actor: "op"}
	a, b, c := repo.order[0], repo.order[1], repo.order[2]

	entry, err := w.Approve(context.Background(), m, a)
	if err != nil || entry.Status != authentication.WaitlistApproved || entry.ExpiresAt == nil {
		t.Fatalf("approve: %+v %v", entry, err)
	}
	s.WaitDeliveries(time.Second)
	if len(delivery.got) != 1 {
		t.Fatalf("delivery: %+v", delivery.got)
	}
	got := delivery.got[0]
	if got.Purpose != authentication.PurposeWaitlistApproved || got.Token != "refresh" || !strings.HasPrefix(got.Link, "https://app.example.com/signup?waitlist=") || got.ExpiresAt == nil {
		t.Fatalf("approval email: %+v", got)
	}
	if left := got.ExpiresAt.Sub(time.Now()); left > config.WaitlistApprovalTTL || left < config.WaitlistApprovalTTL-time.Minute {
		t.Fatalf("ttl: %v", left)
	}

	if _, err = w.Reject(context.Background(), m, b, authentication.WaitlistRejection{}); err != nil {
		t.Fatal(err)
	}
	s.WaitDeliveries(time.Second)
	if len(delivery.got) != 1 {
		t.Fatalf("silent reject sent mail: %+v", delivery.got)
	}
	if _, err = w.Reject(context.Background(), m, c, authentication.WaitlistRejection{Notify: true}); err != nil {
		t.Fatal(err)
	}
	s.WaitDeliveries(time.Second)
	if len(delivery.got) != 2 || delivery.got[1].Purpose != authentication.PurposeWaitlistRejected {
		t.Fatalf("notify reject: %+v", delivery.got)
	}
	if _, err = w.Approve(context.Background(), m, b); code(err) != authentication.CodeWaitlistNotPending {
		t.Fatalf("approve rejected: %v", err)
	}
	if err = w.Delete(context.Background(), m, b); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Find(context.Background(), m.Environment, b); err == nil {
		t.Fatal("deleted entry found")
	}
}

// Bulk approval is capped and reports what is left; listed entries that
// cannot be approved are skipped.
func TestWaitlistApproveMany(t *testing.T) {
	emails := make([]string, config.WaitlistMaxApprove+3)
	for i := range emails {
		emails[i] = "u" + identity.NewWaitlistEntryID().String()[:8] + "@example.com"
	}
	repo := newWaitlistRepo(emails...)
	w, s := waitlistsFor(repo, &recordingDelivery{})
	m := authentication.Mutation{Environment: testBoundary().EnvironmentID, Actor: "op"}
	out, err := w.ApproveMany(context.Background(), m, authentication.WaitlistApprove{AllPending: true})
	if err != nil || out.Approved != config.WaitlistMaxApprove || !out.More || out.Skipped != 0 {
		t.Fatalf("%+v %v", out, err)
	}
	s.WaitDeliveries(5 * time.Second)
	out, err = w.ApproveMany(context.Background(), m, authentication.WaitlistApprove{AllPending: true})
	if err != nil || out.Approved != 3 || out.More {
		t.Fatalf("rest: %+v %v", out, err)
	}
	s.WaitDeliveries(5 * time.Second)

	one := newWaitlistRepo("x@example.com")
	w, _ = waitlistsFor(one, &recordingDelivery{})
	out, err = w.ApproveMany(context.Background(), m, authentication.WaitlistApprove{IDs: []identity.WaitlistEntryID{one.order[0], identity.NewWaitlistEntryID()}})
	if err != nil || out.Approved != 1 || out.Skipped != 1 {
		t.Fatalf("listed: %+v %v", out, err)
	}
	if _, err = w.ApproveMany(context.Background(), m, authentication.WaitlistApprove{}); err == nil {
		t.Fatal("empty selection accepted")
	}
}

func TestWaitlistValidate(t *testing.T) {
	for name, f := range map[string]authentication.WaitlistFilter{"status": {Status: "bogus"}, "email": {Email: strings.Repeat("a", 321)}} {
		if f.Validate() == nil {
			t.Fatalf("filter %s accepted", name)
		}
	}
	for _, ok := range []authentication.WaitlistFilter{{}, {Status: authentication.WaitlistApproved, Email: "ada"}} {
		if err := ok.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	id := identity.NewWaitlistEntryID()
	for name, a := range map[string]authentication.WaitlistApprove{
		"empty":   {},
		"both":    {IDs: []identity.WaitlistEntryID{id}, AllPending: true},
		"zero id": {IDs: []identity.WaitlistEntryID{{}}},
		"too many": {IDs: func() []identity.WaitlistEntryID {
			ids := make([]identity.WaitlistEntryID, config.WaitlistMaxApprove+1)
			for i := range ids {
				ids[i] = id
			}
			return ids
		}()},
	} {
		if a.Validate() == nil {
			t.Fatalf("approve %s accepted", name)
		}
	}
	if err := (authentication.WaitlistApprove{AllPending: true}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSignInPolicyWaitlistValidate(t *testing.T) {
	p := authentication.DefaultSignInPolicy()
	p.Waitlist = ptrx.Bool(true)
	if p.Validate() == nil {
		t.Fatal("waitlist without allow_signup accepted")
	}
	p = waitlistPolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.WaitlistAutoApproveDomains = []string{"not a domain"}
	if p.Validate() == nil {
		t.Fatal("bad domain accepted")
	}
	p = waitlistPolicy()
	p.WaitlistAutoApproveDomains = make([]string, config.WaitlistMaxDomains+1)
	for i := range p.WaitlistAutoApproveDomains {
		p.WaitlistAutoApproveDomains[i] = "a.example"
	}
	if p.Validate() == nil {
		t.Fatal("too many domains accepted")
	}
	p = waitlistPolicy()
	p.WaitlistSignupURL = ptrx.String("http://app.example.com/signup")
	if p.Validate() == nil {
		t.Fatal("plain http signup url accepted")
	}
	if !waitlistPolicy().AutoApproves("Ada@VIP.example") || waitlistPolicy().AutoApproves("ada@other.example") {
		t.Fatal("auto approve")
	}
}

// A sign-up begun while the waitlist was off cannot complete once it is
// on: it has no approved entry.
func TestCompleteSignupStaleAfterWaitlistOn(t *testing.T) {
	store := newSignupStore()
	s := signupService(store, signupPolicy(), &recordingDelivery{})
	id, err := startSignup(s, signupInput())
	if err != nil {
		t.Fatal(err)
	}
	s.WaitDeliveries(time.Second)
	withSignIn(s, waitlistPolicy())
	if _, err = s.CompleteSignup(context.Background(), testBoundary().EnvironmentID, id, "12345678"); err == nil || len(store.joined) != 0 {
		t.Fatalf("stale sign-up completed: %v joined=%d", err, len(store.joined))
	}
}

// Omitting the waitlist fields on update keeps them (fail closed).
func TestSetSignInPolicyKeepsWaitlist(t *testing.T) {
	saver := &signInSaver{stored: waitlistPolicy()}
	p := NewSignInPolicies(saver)
	in := signupPolicy()
	in.Waitlist, in.WaitlistAutoApproveDomains, in.WaitlistSignupURL = nil, nil, nil
	got, err := p.SetSignInPolicy(context.Background(), authentication.Mutation{Environment: testBoundary().EnvironmentID}, in)
	if err != nil || !got.WaitlistOn() || got.WaitlistURL() != "https://app.example.com/signup" || len(got.WaitlistAutoApproveDomains) != 1 {
		t.Fatalf("kept: %+v %v", got, err)
	}
	in.Waitlist, in.WaitlistAutoApproveDomains = ptrx.Bool(false), []string{}
	if got, err = p.SetSignInPolicy(context.Background(), authentication.Mutation{Environment: testBoundary().EnvironmentID}, in); err != nil || got.WaitlistOn() || len(got.WaitlistAutoApproveDomains) != 0 {
		t.Fatalf("explicit off: %+v %v", got, err)
	}
}

// signInSaver stores the policy it is given.
type signInSaver struct {
	authentication.SignInPolicyRepository
	stored authentication.SignInPolicy
}

func (s *signInSaver) GetSignInPolicy(context.Context, identity.EnvironmentID) (authentication.SignInPolicy, error) {
	return s.stored, nil
}
func (s *signInSaver) SetSignInPolicy(_ context.Context, _ authentication.Mutation, p authentication.SignInPolicy) error {
	s.stored = p
	return nil
}
func (s *signInSaver) SignupTarget(context.Context, identity.EnvironmentID, identity.OrganizationID, identity.GroupID) (bool, bool, error) {
	return true, true, nil
}
func (s *signInSaver) SignupOriginAllowed(_ context.Context, _ identity.EnvironmentID, origin string) (bool, error) {
	return origin == "https://app.example.com", nil
}

// The sign-up page must be IAMKit's own origin or a client's allowed
// origin: anywhere else would receive the approval tokens.
func TestSetSignInPolicySignupURLAllowlist(t *testing.T) {
	env := authentication.Mutation{Environment: testBoundary().EnvironmentID}
	p := NewSignInPolicies(&signInSaver{stored: waitlistPolicy()})
	p.SetIssuer("https://iam.example.org")
	in := waitlistPolicy()
	for url, want := range map[string]bool{
		"https://app.example.com/signup":     true,
		"https://APP.example.com:443/signup": true,
		"https://iam.example.org/hosted/up":  true,
		"https://evil.example.net/signup":    false,
		"https://app.example.com:8443/x":     false,
		"https://iam.example.org.evil.net/x": false,
		"":                                   true,
	} {
		in.WaitlistSignupURL = ptrx.String(url)
		_, err := p.SetSignInPolicy(context.Background(), env, in)
		if (err == nil) != want || (err != nil && !strings.Contains(message(err), "waitlist_signup_url must be")) {
			t.Fatalf("%q: allowed=%v err=%v", url, want, err)
		}
	}
}

// An approval whose sign-up page lost its origin still carries the token,
// without a link; the bulk path too.
func TestWaitlistApproveDropsUnlistedLink(t *testing.T) {
	repo := newWaitlistRepo("a@example.com", "b@example.com")
	delivery := &recordingDelivery{}
	w, s := waitlistsFor(repo, delivery)
	policy := waitlistPolicy()
	s.SetSignInPolicies(NewSignInPolicies(signInRepository{policy: &policy})) // no client lists any origin
	m := authentication.Mutation{Environment: testBoundary().EnvironmentID, Actor: "op"}
	if _, err := w.Approve(context.Background(), m, repo.order[0]); err != nil {
		t.Fatal(err)
	}
	if out, err := w.ApproveMany(context.Background(), m, authentication.WaitlistApprove{IDs: []identity.WaitlistEntryID{repo.order[1]}}); err != nil || out.Approved != 1 {
		t.Fatalf("%+v %v", out, err)
	}
	s.WaitDeliveries(time.Second)
	if len(delivery.got) != 2 {
		t.Fatalf("delivery: %+v", delivery.got)
	}
	for _, got := range delivery.got {
		if got.Link != "" || got.Token == "" {
			t.Fatalf("approval email: %+v", got)
		}
	}
}

func TestWaitlistLink(t *testing.T) {
	if got := authentication.WaitlistLink("https://app.example.com/signup?x=1", "ik_wait_t"); got != "https://app.example.com/signup?waitlist=ik_wait_t&x=1" {
		t.Fatal(got)
	}
	if authentication.WaitlistLink("", "t") != "" {
		t.Fatal("link without base")
	}
}
