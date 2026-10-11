package orgadminsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// SetupLinks issues, revokes and exchanges organization setup links. The
// issuer is IAMKit's public URL: links point at the portal served there.
type SetupLinks struct {
	repository orgadmin.SetupLinkRepository
	secrets    orgadmin.SetupSecrets
	issuer     string
	now        func() time.Time
}

var _ orgadmin.SetupLinkCommands = (*SetupLinks)(nil)
var _ orgadmin.SetupLinkQueries = (*SetupLinks)(nil)

func NewSetupLinks(repository orgadmin.SetupLinkRepository, secrets orgadmin.SetupSecrets, issuer string) *SetupLinks {
	return &SetupLinks{repository: repository, secrets: secrets, issuer: issuer, now: time.Now}
}

// Action names of the setup link's audit events (create and revoke are
// audited by their HTTP method and path, see event.Classify).
const ActionSetupLinkUsed = "org_setup_link.used"

// SetupURL is the link an administrator opens: the secret rides in the
// fragment, which browsers never send to servers.
func SetupURL(issuer string, environment identity.EnvironmentID, secret string) string {
	return strings.TrimRight(issuer, "/") + orgadmin.PortalPath + "/" + environment.String() + "/setup#" + secret
}

func (s *SetupLinks) Create(ctx context.Context, m orgadmin.SetupMutation, input orgadmin.SetupLinkInput) (orgadmin.IssuedSetupLink, error) {
	if err := input.Validate(); err != nil {
		return orgadmin.IssuedSetupLink{}, err
	}
	ttl, _ := input.TTL()
	secret, hash, err := s.secrets.Generate(orgadmin.SetupLinkPrefix)
	if err != nil {
		return orgadmin.IssuedSetupLink{}, err
	}
	link := orgadmin.SetupLink{ID: identity.NewSetupLinkID(), Intents: input.Normalized(), ExpiresAt: s.now().Add(ttl).UTC(), CreatedBy: m.Actor}
	if err := s.repository.Create(ctx, m, link, hash); err != nil {
		return orgadmin.IssuedSetupLink{}, err
	}
	return orgadmin.IssuedSetupLink{ID: link.ID, URL: SetupURL(s.issuer, m.Environment, secret), ExpiresAt: link.ExpiresAt, Intents: link.Intents}, nil
}

func (s *SetupLinks) Revoke(ctx context.Context, m orgadmin.SetupMutation, link identity.SetupLinkID) error {
	return s.repository.Revoke(ctx, m, link)
}

func (s *SetupLinks) List(ctx context.Context, environment identity.EnvironmentID, organization identity.OrganizationID, page query.Pagination) (query.Paginated[orgadmin.SetupLink], error) {
	return s.repository.List(ctx, environment, organization, page)
}

func (s *SetupLinks) Exchange(ctx context.Context, token string) (orgadmin.SetupSession, error) {
	if !strings.HasPrefix(token, orgadmin.SetupLinkPrefix) || len(token) > 256 {
		return orgadmin.SetupSession{}, errx.Unauthorized("invalid or expired setup link")
	}
	bearer, bearerHash, err := s.secrets.Generate(orgadmin.SetupSessionPrefix)
	if err != nil {
		return orgadmin.SetupSession{}, err
	}
	out, err := s.repository.Exchange(ctx, s.secrets.Hash(token), bearerHash, config.SetupSessionTTL)
	if err != nil {
		return orgadmin.SetupSession{}, err
	}
	return orgadmin.SetupSession{
		AccessToken: bearer, TokenType: "Bearer", ExpiresIn: int(time.Until(out.ExpiresAt).Seconds()),
		EnvironmentID: out.Grant.Environment, OrganizationID: out.Grant.Organization,
		Intents: out.Grant.Intents, OrganizationName: out.OrganizationName,
	}, nil
}

func (s *SetupLinks) Session(ctx context.Context, bearer string) (orgadmin.SetupGrant, error) {
	if !strings.HasPrefix(bearer, orgadmin.SetupSessionPrefix) || len(bearer) > 256 {
		return orgadmin.SetupGrant{}, errx.Unauthorized("invalid or expired setup link")
	}
	return s.repository.Session(ctx, s.secrets.Hash(bearer))
}

// Setup links of the organization, managed by its owners.

func setupMutation(p orgadmin.Principal) orgadmin.SetupMutation {
	return orgadmin.SetupMutation{Environment: p.Environment, Organization: p.Organization, Actor: p.Actor(), Action: p.Action, Target: p.Target}
}

func (s *Service) CreateSetupLink(ctx context.Context, p orgadmin.Principal, input orgadmin.SetupLinkInput) (orgadmin.IssuedSetupLink, error) {
	if err := p.RequireOwner(); err != nil {
		return orgadmin.IssuedSetupLink{}, err
	}
	return s.d.SetupLinks.Create(ctx, setupMutation(p), input)
}

func (s *Service) RevokeSetupLink(ctx context.Context, p orgadmin.Principal, link identity.SetupLinkID) error {
	if err := p.RequireOwner(); err != nil {
		return err
	}
	return s.d.SetupLinks.Revoke(ctx, setupMutation(p), link)
}

func (s *Service) SetupLinks(ctx context.Context, p orgadmin.Principal, page query.Pagination) (query.Paginated[orgadmin.SetupLink], error) {
	if err := p.RequireOwner(); err != nil {
		return query.Paginated[orgadmin.SetupLink]{}, err
	}
	return s.d.SetupLinkViews.List(ctx, p.Environment, p.Organization, page)
}
