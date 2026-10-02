package orgadminsvc

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Portals turns the hosted organization admin portal on and off. The
// issuer is IAMKit's public URL: the portal is served there, so its
// client's redirect URIs are derived from it.
type Portals struct {
	repository orgadmin.PortalRepository
	issuer     string
}

var _ orgadmin.PortalCommands = (*Portals)(nil)
var _ orgadmin.PortalQueries = (*Portals)(nil)

func NewPortals(repository orgadmin.PortalRepository, issuer string) *Portals {
	return &Portals{repository: repository, issuer: issuer}
}

// Action names of the portal's audit events.
const (
	ActionPortalEnabled  = "org_admin_portal.enabled"
	ActionPortalDisabled = "org_admin_portal.disabled"
)

func (s *Portals) Portal(ctx context.Context, environment identity.EnvironmentID) (orgadmin.Portal, error) {
	out, err := s.repository.Portal(ctx, environment)
	if err != nil {
		return out, err
	}
	return s.withURL(environment, out), nil
}

func (s *Portals) EnablePortal(ctx context.Context, m orgadmin.PortalMutation) (orgadmin.Portal, error) {
	redirects, err := orgadmin.NewPortalRedirects(s.issuer, m.Environment)
	if err != nil {
		return orgadmin.Portal{}, err
	}
	m.Action, m.Target = ActionPortalEnabled, ""
	out, err := s.repository.EnablePortal(ctx, m, identity.NewApplicationID(), identity.NewClientID(), redirects)
	if err != nil {
		return out, err
	}
	return s.withURL(m.Environment, out), nil
}

func (s *Portals) DisablePortal(ctx context.Context, m orgadmin.PortalMutation) error {
	m.Action, m.Target = ActionPortalDisabled, ""
	return s.repository.DisablePortal(ctx, m)
}

// withURL fills the sign-in URL of an enabled portal.
func (s *Portals) withURL(environment identity.EnvironmentID, p orgadmin.Portal) orgadmin.Portal {
	if !p.Enabled {
		return p
	}
	if redirects, err := orgadmin.NewPortalRedirects(s.issuer, environment); err == nil {
		p.URL = redirects.SignedOut
	}
	return p
}
