package orgadminsvc

import (
	"context"
	"errors"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type fakePortal struct {
	portal    orgadmin.Portal
	redirects orgadmin.PortalRedirects
	mutations []orgadmin.PortalMutation
}

func (f *fakePortal) Portal(context.Context, identity.EnvironmentID) (orgadmin.Portal, error) {
	return f.portal, nil
}
func (f *fakePortal) EnablePortal(_ context.Context, m orgadmin.PortalMutation, application identity.ApplicationID, client identity.ClientID, redirects orgadmin.PortalRedirects) (orgadmin.Portal, error) {
	f.mutations = append(f.mutations, m)
	f.redirects = redirects
	if f.portal.Client.IsZero() {
		f.portal = orgadmin.Portal{Client: client, Application: application}
	}
	f.portal.Enabled = true
	return f.portal, nil
}
func (f *fakePortal) DisablePortal(_ context.Context, m orgadmin.PortalMutation) error {
	if f.portal.Client.IsZero() {
		return errx.NotFound("the organization admin portal is not enabled")
	}
	f.mutations = append(f.mutations, m)
	f.portal.Enabled = false
	return nil
}

func TestPortalLifecycle(t *testing.T) {
	repo := &fakePortal{}
	s := NewPortals(repo, "https://iam.example/")
	ctx := context.Background()
	if p, _ := s.Portal(ctx, env); p.Enabled || p.URL != "" {
		t.Fatalf("never enabled = %+v", p)
	}
	if err := s.DisablePortal(ctx, orgadmin.PortalMutation{Environment: env}); err == nil {
		t.Fatal("disabled a portal never enabled")
	}
	p, err := s.EnablePortal(ctx, orgadmin.PortalMutation{Environment: env, Actor: "op", Action: "PUT", Target: "/x"})
	base := "https://iam.example/org-admin/" + env.String()
	if err != nil || !p.Enabled || p.Client.IsZero() || p.URL != base {
		t.Fatalf("enable = %+v %v", p, err)
	}
	if repo.redirects.Callback != base+"/callback" || repo.redirects.SignedOut != base {
		t.Fatalf("redirects = %+v", repo.redirects)
	}
	if m := repo.mutations[0]; m.Action != ActionPortalEnabled || m.Target != "" || m.Actor != "op" {
		t.Fatalf("mutation = %+v", m)
	}
	again, _ := s.EnablePortal(ctx, orgadmin.PortalMutation{Environment: env})
	if again.Client != p.Client {
		t.Fatal("enabling again registered another client")
	}
	if err = s.DisablePortal(ctx, orgadmin.PortalMutation{Environment: env}); err != nil || repo.mutations[2].Action != ActionPortalDisabled {
		t.Fatalf("disable = %v %+v", err, repo.mutations)
	}
	if p, _ = s.Portal(ctx, env); p.Enabled || p.URL != "" || p.Client.IsZero() {
		t.Fatalf("disabled = %+v", p)
	}
}

func TestPortalNeedsAnAbsoluteIssuer(t *testing.T) {
	for _, issuer := range []string{"", "iam.example", "ftp://iam.example"} {
		_, err := NewPortals(&fakePortal{}, issuer).EnablePortal(context.Background(), orgadmin.PortalMutation{Environment: env})
		var e *errx.Error
		if !errors.As(err, &e) || e.Type != errx.TypeBusiness {
			t.Fatalf("issuer %q: %v", issuer, err)
		}
	}
}
