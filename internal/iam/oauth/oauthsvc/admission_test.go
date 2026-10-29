package oauthsvc

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// fakeAdmission records what the service decided; unset methods panic.
type fakeAdmission struct {
	oauth.AdmissionRepository
	protected oauth.ProtectedResource
	known     bool
	approved  []oauth.Approval
	blocked   int
	entries   []oauth.AllowlistCreate
	templates []oauth.Registration
	expired   int
}

func (f *fakeAdmission) FindProtectedResource(context.Context, identity.EnvironmentID, identity.ProtectedResourceID) (oauth.ProtectedResource, error) {
	return f.protected, nil
}
func (f *fakeAdmission) FindExternalClient(context.Context, identity.EnvironmentID, identity.ProtectedResourceID, identity.ClientID) (oauth.ExternalClientView, error) {
	if !f.known {
		return oauth.ExternalClientView{}, errx.NotFound("client not found")
	}
	return oauth.ExternalClientView{}, nil
}
func (f *fakeAdmission) ApproveClient(_ context.Context, _ oauth.Mutation, _ identity.ProtectedResourceID, _ identity.ClientID, in oauth.Approval) error {
	f.approved = append(f.approved, in)
	return nil
}
func (f *fakeAdmission) BlockClient(context.Context, oauth.Mutation, identity.ProtectedResourceID, identity.ClientID) error {
	f.blocked++
	return nil
}
func (f *fakeAdmission) FindAllowlistEntry(context.Context, identity.EnvironmentID, identity.AllowlistEntryID) (oauth.AllowlistEntry, error) {
	return oauth.AllowlistEntry{}, nil
}
func (f *fakeAdmission) CreateAllowlistEntry(_ context.Context, _ oauth.Mutation, _ identity.AllowlistEntryID, in oauth.AllowlistCreate) error {
	f.entries = append(f.entries, in)
	return nil
}
func (f *fakeAdmission) CreateTemplateClient(_ context.Context, _ oauth.Mutation, id identity.ClientID, in oauth.Registration) (identity.ClientID, bool, error) {
	f.templates = append(f.templates, in)
	return id, true, nil
}
func (f *fakeAdmission) ExpireApprovals(_ context.Context, limit int) (int, error) {
	if limit != config.ClientExpireBatch {
		return 0, nil
	}
	return f.expired, nil
}
func (f *fakeAdmission) ListExternalClients(context.Context, identity.EnvironmentID, identity.ProtectedResourceID, oauth.ExternalClientFilter, query.Pagination) (query.Paginated[oauth.ExternalClientView], error) {
	return query.Paginated[oauth.ExternalClientView]{}, nil
}

type flag bool

func (f flag) Enabled(context.Context, identity.EnvironmentID, string) (bool, error) {
	return bool(f), nil
}

func admissionMutation() oauth.Mutation {
	return oauth.Mutation{Environment: identity.NewEnvironmentID(), Actor: "op"}
}

func TestApproveValidatesExpiryAndOwnership(t *testing.T) {
	repo := &fakeAdmission{known: true}
	s := NewAdmissions(repo, nil)
	pr, client := identity.NewProtectedResourceID(), identity.NewClientID()
	past := time.Now().Add(-time.Hour)
	if err := s.ApproveClient(context.Background(), admissionMutation(), pr, client, oauth.Approval{MetadataHash: "h", ExpiresAt: &past}); err == nil || len(repo.approved) != 0 {
		t.Fatalf("past expiry accepted: %v", err)
	}
	future := time.Now().Add(time.Hour)
	if err := s.ApproveClient(context.Background(), admissionMutation(), pr, client, oauth.Approval{MetadataHash: "h", ExpiresAt: &future}); err != nil || len(repo.approved) != 1 {
		t.Fatalf("approve: %v %d", err, len(repo.approved))
	}
	// A client of another server is not found, nothing is decided.
	repo.known = false
	if err := s.BlockClient(context.Background(), admissionMutation(), pr, client); err == nil || repo.blocked != 0 {
		t.Fatalf("foreign client blocked: %v", err)
	}
	if err := s.BlockClient(context.Background(), admissionMutation(), identity.ProtectedResourceID{}, client); err == nil {
		t.Fatal("zero protected resource accepted")
	}
}

func TestAllowlistEntryIsResolved(t *testing.T) {
	repo := &fakeAdmission{}
	s := NewAdmissions(repo, flag(false))
	m := admissionMutation()
	if _, err := s.CreateAllowlistEntry(context.Background(), m, oauth.AllowlistCreate{Origin: "http://evil.example", PathPrefix: "/"}); err == nil {
		t.Fatal("insecure origin accepted")
	}
	got, err := s.CreateAllowlistEntry(context.Background(), m, oauth.AllowlistCreate{Preset: "claude_code"})
	_ = got
	if err != nil || len(repo.entries) != 1 || repo.entries[0].Origin != "https://claude.ai" || repo.entries[0].PathPrefix == "" {
		t.Fatalf("preset entry: %v %+v", err, repo.entries)
	}
	if _, err = s.CreateAllowlistEntry(context.Background(), m, oauth.AllowlistCreate{Preset: "cursor"}); err == nil {
		t.Fatal("template preset added to the allowlist")
	}
}

func TestTemplatePresets(t *testing.T) {
	app, res := identity.NewApplicationID(), identity.NewResourceID()
	repo := &fakeAdmission{protected: oauth.ProtectedResource{Application: app, Resource: res}}
	pr := identity.NewProtectedResourceID()
	ctx := context.Background()

	s := NewAdmissions(repo, flag(false))
	out, err := s.CreateClientTemplate(ctx, admissionMutation(), pr, oauth.PresetApply{Preset: "gemini_cli"})
	if err != nil || out.Client == nil || !out.Client.LoopbackAnyPort || !out.Client.Created {
		t.Fatalf("gemini_cli: %v %+v", err, out)
	}
	r := repo.templates[0]
	if r.Application != app || r.Resource != res || !r.Public || !r.HostedLogin || r.Preset != "gemini_cli" || r.ClientAuth.Method != "none" || !r.LoopbackAnyPort {
		t.Fatalf("registration: %+v", r)
	}
	// Inspector only in development; documents are not templates.
	if _, err = s.CreateClientTemplate(ctx, admissionMutation(), pr, oauth.PresetApply{Preset: "mcp_inspector"}); err == nil {
		t.Fatal("inspector created outside development")
	}
	if _, err = s.CreateClientTemplate(ctx, admissionMutation(), pr, oauth.PresetApply{Preset: "claude_code"}); err == nil {
		t.Fatal("metadata document preset made a client")
	}
	if _, err = s.CreateClientTemplate(ctx, admissionMutation(), pr, oauth.PresetApply{}); err == nil {
		t.Fatal("empty preset accepted")
	}
	dev := NewAdmissions(repo, flag(true))
	if _, err = dev.CreateClientTemplate(ctx, admissionMutation(), pr, oauth.PresetApply{Preset: "mcp_inspector"}); err != nil {
		t.Fatalf("inspector in development: %v", err)
	}
	// The catalog follows the feature.
	for _, c := range []struct {
		s    *Admissions
		want bool
	}{{s, false}, {dev, true}} {
		list, err := c.s.ListPresets(ctx, identity.NewEnvironmentID())
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, p := range list {
			found = found || p.Key == "mcp_inspector"
		}
		if found != c.want {
			t.Fatalf("inspector listed = %v, want %v", found, c.want)
		}
	}
}

func TestExpireReportsMore(t *testing.T) {
	repo := &fakeAdmission{expired: config.ClientExpireBatch}
	s := NewAdmissions(repo, nil)
	if more, err := s.ExpireApprovals(context.Background()); err != nil || !more {
		t.Fatalf("full batch: %v %v", more, err)
	}
	repo.expired = 1
	if more, err := s.ExpireApprovals(context.Background()); err != nil || more {
		t.Fatalf("short batch: %v %v", more, err)
	}
}

func TestListClientsRejectsBadFilter(t *testing.T) {
	s := NewAdmissions(&fakeAdmission{}, nil)
	if _, err := s.ListExternalClients(context.Background(), identity.NewEnvironmentID(), identity.NewProtectedResourceID(), oauth.ExternalClientFilter{Admission: "bogus"}, query.Pagination{}); err == nil {
		t.Fatal("bogus admission accepted")
	}
}

func TestRefused(t *testing.T) {
	c := &oauth.Client{Environment: identity.NewEnvironmentID(), ExternalID: "https://claude.ai/x", Name: "N"}
	err := oauth.Refused(oauth.ErrClientBlocked(), c)
	if !oauth.IsClientRefusal(err) {
		t.Fatal("not a refusal")
	}
	if oauth.Refused(oauth.ErrClientBlocked(), nil) == nil {
		t.Fatal("nil client dropped the error")
	}
	if oauth.IsClientRefusal(oauth.ErrInvalidTarget("x")) {
		t.Fatal("unrelated error is a refusal")
	}
}
