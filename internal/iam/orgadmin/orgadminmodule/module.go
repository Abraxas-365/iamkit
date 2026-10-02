// Package orgadminmodule assembles organization administration.
package orgadminmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin/adapters/orgadminhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin/adapters/orgadminpg"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin/orgadminsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB     *sqlx.DB
	Caller func(*fiber.Ctx) orgadminhttp.Caller
	// Issuer is IAMKit's public URL, where the portal is served.
	Issuer string
	// ActorID names the operator behind a portal change.
	ActorID             func(*fiber.Ctx) string
	Users               user.Commands
	UserQueries         user.Queries
	Organizations       organization.Commands
	OrganizationViews   organization.Queries
	Domains             organization.DomainCommands
	DomainViews         organization.DomainQueries
	Grants              authorization.GrantCommands
	GrantViews          authorization.GrantQueries
	ResourceViews       authorization.ResourceQueries
	ResourceGrants      authorization.ResourceGrantCommands
	ResourceGrantViews  authorization.ResourceGrantQueries
	Invitations         invitation.Commands
	InvitationViews     invitation.Queries
	Connections         federation.Commands
	ConnectionViews     federation.Queries
	Branding            hosted.Commands
	BrandingViews       hosted.Queries
	PasswordPolicies    authentication.PasswordPolicyCommands
	PasswordPolicyViews authentication.PasswordPolicyQueries
}

type Module struct {
	Commands orgadmin.Commands
	Queries  orgadmin.Queries
	HTTP     *orgadminhttp.Handler
	// Portal is the hosted organization admin portal.
	PortalCommands orgadmin.PortalCommands
	PortalQueries  orgadmin.PortalQueries
	PortalHTTP     *orgadminhttp.Portal
}

func New(deps Deps) Module {
	service := orgadminsvc.New(orgadminsvc.Deps{
		Repository: orgadminpg.New(deps.DB),
		Users:      deps.Users, UserQueries: deps.UserQueries,
		Organizations: deps.Organizations, OrganizationViews: deps.OrganizationViews,
		Domains: deps.Domains, DomainViews: deps.DomainViews,
		Grants: deps.Grants, GrantViews: deps.GrantViews,
		ResourceViews: deps.ResourceViews, ResourceGrants: deps.ResourceGrants, ResourceGrantViews: deps.ResourceGrantViews,
		Invitations: deps.Invitations, InvitationViews: deps.InvitationViews,
		Connections: deps.Connections, ConnectionViews: deps.ConnectionViews,
		Branding: deps.Branding, BrandingViews: deps.BrandingViews,
		PasswordPolicies: deps.PasswordPolicies, PasswordPolicyViews: deps.PasswordPolicyViews,
	})
	portals := orgadminsvc.NewPortals(orgadminpg.NewPortal(deps.DB), deps.Issuer)
	return Module{Commands: service, Queries: service, HTTP: orgadminhttp.New(service, service, deps.Caller),
		PortalCommands: portals, PortalQueries: portals, PortalHTTP: orgadminhttp.NewPortal(portals, portals, deps.ActorID)}
}
