package samlsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type logoutRepository struct {
	linked    []samlidp.IdPSession
	ends      []samlidp.Mutation
	endResult bool
	due       []samlidp.LogoutNotification
	delivered []int64
	retried   map[int64]time.Time
	failed    []int64
	pruned    time.Time
}

func (r *logoutRepository) RememberSession(ctx context.Context, s samlidp.IdPSession) error {
	r.linked = append(r.linked, s)
	return nil
}
func (r *logoutRepository) EndSession(ctx context.Context, m samlidp.Mutation, provider identity.ServiceProviderID, session identity.SessionID, nameID string) (bool, error) {
	r.ends = append(r.ends, m)
	return r.endResult && nameID == "ada@example.com", nil
}
func (r *logoutRepository) ClaimLogouts(ctx context.Context, limit int) ([]samlidp.LogoutNotification, error) {
	due := r.due
	r.due = nil
	return due, nil
}
func (r *logoutRepository) LogoutDelivered(ctx context.Context, id int64) error {
	r.delivered = append(r.delivered, id)
	return nil
}
func (r *logoutRepository) LogoutRetry(ctx context.Context, id int64, next time.Time, problem string) error {
	if r.retried == nil {
		r.retried = map[int64]time.Time{}
	}
	r.retried[id] = next
	return nil
}
func (r *logoutRepository) LogoutFailed(ctx context.Context, n samlidp.LogoutNotification, problem string) error {
	r.failed = append(r.failed, n.ID)
	return nil
}
func (r *logoutRepository) PruneLogouts(ctx context.Context, before time.Time) error {
	r.pruned = before
	return nil
}

type logoutProtocol struct {
	request  samlidp.LogoutRequest
	verify   error
	statuses []string
}

func (p *logoutProtocol) DecodeLogout(m samlidp.LogoutMessage) (samlidp.LogoutRequest, error) {
	return p.request, nil
}
func (p *logoutProtocol) VerifyLogout(m samlidp.LogoutMessage, sp samlidp.ServiceProvider) error {
	return p.verify
}
func (p *logoutProtocol) LogoutResponse(ctx context.Context, environment identity.EnvironmentID, sp samlidp.ServiceProvider, request samlidp.LogoutRequest, status string) (samlidp.LogoutAnswer, error) {
	p.statuses = append(p.statuses, status)
	return samlidp.LogoutAnswer{Environment: environment, URL: sp.SLOURL + "?" + status}, nil
}
func (p *logoutProtocol) BackchannelLogout(ctx context.Context, n samlidp.LogoutNotification) ([]byte, error) {
	return []byte("<soap/>"), nil
}

type sender struct {
	err  error
	urls []string
}

func (s *sender) Send(ctx context.Context, url string, envelope []byte) error {
	s.urls = append(s.urls, url)
	return s.err
}

const certificate = "unused-by-the-fake-protocol"

func logoutSetup(t *testing.T) (*Service, *logoutRepository, *logoutProtocol, *sender, samlidp.ServiceProvider) {
	t.Helper()
	svc, repo, proto, sp := setup(t)
	sp.SLOURL, sp.SLOBinding, sp.SLOSOAPURL, sp.Certificate = "https://wiki.example.com/slo", samlidp.SLOBindingRedirect, "https://wiki.example.com/soap", certificate
	repo.providers[sp.ID] = sp
	logoutRepo := &logoutRepository{endResult: true}
	logoutProto := &logoutProtocol{request: samlidp.LogoutRequest{ID: "r1", Issuer: sp.EntityID, NameID: "ada@example.com", IssueInstant: svc.now(), SessionIndexes: []string{identity.NewSessionID().String()}}}
	out := &sender{}
	svc.SetLogout(logoutRepo, logoutProto, out)
	_ = proto
	return svc, logoutRepo, logoutProto, out, sp
}

func TestFinishRemembersSessionsOfLogoutProviders(t *testing.T) {
	svc, repo, _, sp := setup(t)
	logoutRepo := &logoutRepository{}
	svc.SetLogout(logoutRepo, &logoutProtocol{}, &sender{})
	ctx := context.Background()
	finish := func() identity.SessionID {
		ticket, binding, err := svc.Begin(ctx, sp.Environment, samlidp.Message{Redirect: true, SAMLRequest: "x"})
		if err != nil {
			t.Fatal(err)
		}
		login := samlidp.Login{User: identity.NewUserID(), Session: identity.NewSessionID()}
		if _, err := svc.Finish(ctx, ticket, binding, login); err != nil {
			t.Fatal(err)
		}
		return login.Session
	}
	finish()
	if len(logoutRepo.linked) != 0 {
		t.Fatalf("a provider without single logout was linked: %+v", logoutRepo.linked)
	}
	sp.SLOSOAPURL, sp.Certificate = "https://wiki.example.com/soap", certificate
	repo.providers[sp.ID] = sp
	session := finish()
	if len(logoutRepo.linked) != 1 || logoutRepo.linked[0].Session != session || logoutRepo.linked[0].ServiceProvider != sp.ID || logoutRepo.linked[0].NameID != "ada@example.com" || logoutRepo.linked[0].Environment != sp.Environment {
		t.Fatalf("linked: %+v", logoutRepo.linked)
	}
}

func TestLogoutEndsSession(t *testing.T) {
	svc, repo, proto, _, sp := logoutSetup(t)
	answer, err := svc.Logout(context.Background(), sp.Environment, samlidp.LogoutMessage{Redirect: true, SAMLRequest: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(proto.statuses) != 1 || proto.statuses[0] != samlidp.StatusSuccess || answer.URL != sp.SLOURL+"?"+samlidp.StatusSuccess {
		t.Fatalf("answer: %+v statuses %v", answer, proto.statuses)
	}
	if len(repo.ends) != 1 || repo.ends[0].Action != samlidp.ActionLogout || repo.ends[0].Target != sp.ID.String() || repo.ends[0].Environment != sp.Environment {
		t.Fatalf("ends: %+v", repo.ends)
	}
}

func TestLogoutUnknownSessionNeverLeaks(t *testing.T) {
	svc, repo, proto, _, sp := logoutSetup(t)
	repo.endResult = false
	if _, err := svc.Logout(context.Background(), sp.Environment, samlidp.LogoutMessage{Redirect: true, SAMLRequest: "x"}); err != nil {
		t.Fatal(err)
	}
	if proto.statuses[0] != samlidp.StatusRequester {
		t.Fatalf("status %v", proto.statuses)
	}
	// A request without a usable SessionIndex ends nothing.
	proto.request.SessionIndexes = []string{"not-a-session"}
	if _, err := svc.Logout(context.Background(), sp.Environment, samlidp.LogoutMessage{Redirect: true, SAMLRequest: "x"}); err != nil || proto.statuses[1] != samlidp.StatusRequester {
		t.Fatalf("statuses %v err %v", proto.statuses, err)
	}
}

func TestLogoutRefuses(t *testing.T) {
	svc, repo, proto, _, sp := logoutSetup(t)
	ctx := context.Background()
	message := samlidp.LogoutMessage{Redirect: true, SAMLRequest: "x"}
	proto.verify = errors.New("bad signature")
	if _, err := svc.Logout(ctx, sp.Environment, message); err == nil {
		t.Fatal("unverified request accepted")
	}
	proto.verify = nil
	proto.request.Issuer = "https://unknown.example.com"
	if _, err := svc.Logout(ctx, sp.Environment, message); err == nil {
		t.Fatal("unknown issuer accepted")
	}
	proto.request.Issuer = sp.EntityID
	proto.request.IssueInstant = svc.now().Add(-time.Hour)
	if _, err := svc.Logout(ctx, sp.Environment, message); err == nil {
		t.Fatal("expired request accepted")
	}
	proto.request.IssueInstant = svc.now()
	other := sp
	other.Certificate = ""
	repo2 := svc.repository.(*repository)
	repo2.providers[sp.ID] = other
	if _, err := svc.Logout(ctx, sp.Environment, message); err == nil {
		t.Fatal("provider without a certificate accepted")
	}
	if len(repo.ends) != 0 {
		t.Fatalf("sessions ended by refused requests: %+v", repo.ends)
	}
}

func TestDispatchLogouts(t *testing.T) {
	svc, repo, _, out, sp := logoutSetup(t)
	ctx := context.Background()
	n := func(id int64, attempts int) samlidp.LogoutNotification {
		return samlidp.LogoutNotification{ID: id, Environment: sp.Environment, ServiceProvider: sp, Session: identity.NewSessionID(), NameID: "ada@example.com", Attempts: attempts}
	}
	repo.due = []samlidp.LogoutNotification{n(1, 1)}
	more, err := svc.DispatchLogouts(ctx)
	if err != nil || more {
		t.Fatalf("more=%v err=%v", more, err)
	}
	if len(repo.delivered) != 1 || repo.delivered[0] != 1 || out.urls[0] != sp.SLOSOAPURL {
		t.Fatalf("delivered %v urls %v", repo.delivered, out.urls)
	}
	out.err = errors.New("connection refused")
	repo.due = []samlidp.LogoutNotification{n(2, 3), n(3, samlidp.LogoutMaxAttempts)}
	if _, err := svc.DispatchLogouts(ctx); err != nil {
		t.Fatal(err)
	}
	if want := svc.now().Add(samlidp.LogoutRetryAfter(3)); !repo.retried[2].Equal(want) {
		t.Fatalf("retry at %v, want %v", repo.retried[2], want)
	}
	if len(repo.failed) != 1 || repo.failed[0] != 3 || len(repo.delivered) != 1 {
		t.Fatalf("failed %v delivered %v", repo.failed, repo.delivered)
	}
}

func TestPruneLogouts(t *testing.T) {
	svc, repo, _, _, _ := logoutSetup(t)
	if err := svc.PruneLogouts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := svc.now().Add(-samlidp.LogoutRetention); !repo.pruned.Equal(want) {
		t.Fatalf("pruned before %v, want %v", repo.pruned, want)
	}
}

func TestCreateAndUpdateValidateLogout(t *testing.T) {
	svc, _, _, sp := setup(t)
	ctx := context.Background()
	m := samlidp.Mutation{Environment: sp.Environment, Actor: "op"}
	create := samlidp.Create{Name: "App", Application: identity.NewApplicationID(), Resource: identity.NewResourceID(), EntityID: "https://app.example.com", ACSURLs: []string{"https://app.example.com/acs"}, SLOSOAPURL: "https://app.example.com/soap"}
	if _, err := svc.Create(ctx, m, create); err == nil {
		t.Fatal("a back-channel URL without a certificate accepted")
	}
	create.SLOSOAPURL = "http://app.example.com/soap"
	create.Certificate = certificate
	if _, err := svc.Create(ctx, m, create); err == nil {
		t.Fatal("an invalid certificate and plain http accepted")
	}
	soap := "https://wiki.example.com/soap"
	if _, err := svc.Update(ctx, m, sp.ID, samlidp.Update{SLOSOAPURL: &soap}); err == nil {
		t.Fatal("update enabled single logout without a certificate")
	}
}
