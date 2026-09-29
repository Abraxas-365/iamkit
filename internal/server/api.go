package server

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/server/apiauth"
	"github.com/gofiber/fiber/v2"
)

// apiRoutes registers the /api/v1/* route group, which accepts JWT tokens
// (from machine-token or user login) and enforces scoped IAM permissions.
// Handlers are the same as management but wired with JWT-based auth.
//
// Groups whose routes share no path prefix use guarded, never
// e.Group("", check): Fiber runs a prefix-less group's middleware for every
// later route under the environment, so its permission check would also
// guard unrelated routes (e.g. delivery would demand iam:members:read).
// For the same reason /organizations and /applications use guarded: a
// prefix group there would also demand iam:orgs:* / iam:apps:* on the
// member (/organizations/:organization/…) and resource
// (/applications/:application/resources) routes registered after them.
//
// apiauth.Scope sits on the group that binds :environment; Authenticate
// runs on /api/v1, before that parameter exists.
func (s *Server) apiRoutes(app *fiber.App, rateLimit int) {
	if s.API == nil {
		return
	}
	api := app.Group("/api/v1", s.API.Authenticate, rateLimiter(rateLimit))
	e := api.Group("/environments/:environment", apiauth.Scope)

	// Users
	users := e.Group("/users", apiauth.ReadWrite(authorization.PermUsersRead, authorization.PermUsersWrite))
	users.Post("/", s.APIHandlers.Users.Create)
	users.Get("/", s.APIHandlers.Users.List)
	users.Get("/:id", s.APIHandlers.Users.Find)
	users.Patch("/:id", s.APIHandlers.Users.Update)
	users.Delete("/:id", s.APIHandlers.Users.Suspend)
	users.Delete("/:id/permanent", s.APIHandlers.Users.Delete)
	if s.APIHandlers.Factors != nil {
		users.Get("/:id/factors", s.APIHandlers.Factors.Factors)
		users.Delete("/:id/factors", s.APIHandlers.Factors.Reset)
	}

	// Organizations
	orgs := guarded(e, apiauth.ReadWrite(authorization.PermOrgsRead, authorization.PermOrgsWrite))
	orgs.Post("/organizations", s.APIHandlers.Organizations.Create)
	orgs.Get("/organizations", s.APIHandlers.Organizations.List)
	orgs.Get("/organizations/:id", s.APIHandlers.Organizations.Find)
	orgs.Patch("/organizations/:id", s.APIHandlers.Organizations.Update)

	// Members
	members := guarded(e, apiauth.ReadWrite(authorization.PermMembersRead, authorization.PermMembersWrite))
	members.Post("/memberships", s.APIHandlers.Organizations.AddMember)
	members.Get("/organizations/:organization/members", s.APIHandlers.Organizations.Members)
	members.Patch("/organizations/:organization/members/:user", s.APIHandlers.Organizations.UpdateMember)
	members.Delete("/organizations/:organization/members/:user", s.APIHandlers.Organizations.RemoveMember)

	// Org structure (follows org membership domain)
	structure := e.Group("/organizations/:organization", apiauth.ReadWrite(authorization.PermMembersRead, authorization.PermMembersWrite), s.APIHandlers.Structure.Check)
	s.APIHandlers.Structure.RegisterViews(structure)
	s.APIHandlers.Structure.RegisterMutations(structure)
	if s.APIHandlers.Groups != nil {
		s.APIHandlers.Groups.RegisterViews(structure)
		s.APIHandlers.Groups.RegisterMutations(structure)
	}
	if s.APIHandlers.Domains != nil {
		s.APIHandlers.Domains.RegisterViews(structure)
		s.APIHandlers.Domains.RegisterMutations(structure)
	}
	if s.APIHandlers.Invitations != nil {
		s.APIHandlers.Invitations.RegisterViews(structure)
		s.APIHandlers.Invitations.RegisterMutations(structure)
	}

	// Applications
	apps := guarded(e, apiauth.ReadWrite(authorization.PermAppsRead, authorization.PermAppsWrite))
	apps.Post("/applications", s.APIHandlers.Applications.Create)
	apps.Get("/applications", s.APIHandlers.Applications.List)
	apps.Get("/applications/:id", s.APIHandlers.Applications.Find)
	apps.Patch("/applications/:id", s.APIHandlers.Applications.Update)

	// Resources
	res := guarded(e, apiauth.ReadWrite(authorization.PermResourcesRead, authorization.PermResourcesWrite))
	res.Post("/resources", s.APIHandlers.Authorization.Create)
	res.Get("/resources", s.APIHandlers.Authorization.List)
	res.Get("/resources/:id", s.APIHandlers.Authorization.Find)
	res.Put("/resources/:id", s.APIHandlers.Authorization.Update)
	res.Post("/application-resources", s.APIHandlers.Authorization.Link)
	res.Delete("/application-resources/:application/:resource", s.APIHandlers.Authorization.Unlink)
	res.Get("/applications/:application/resources", s.APIHandlers.Authorization.ListByApplication)

	// Roles
	roles := guarded(e, apiauth.ReadWrite(authorization.PermRolesRead, authorization.PermRolesWrite))
	roles.Get("/roles", s.APIHandlers.Grants.ListRoles)
	roles.Get("/roles/:id", s.APIHandlers.Grants.ListRoles)
	roles.Post("/roles", s.APIHandlers.Grants.SaveRole)
	roles.Put("/roles/:id", s.APIHandlers.Grants.SaveRole)
	roles.Delete("/roles/:id", s.APIHandlers.Grants.DeleteRole)
	roles.Post("/role-assignments", s.APIHandlers.Grants.Assign)
	roles.Get("/role-assignments", s.APIHandlers.Grants.RoleAssignments)
	roles.Delete("/role-assignments/:role/:organization/:user", s.APIHandlers.Grants.Unassign)
	roles.Post("/group-role-assignments", s.APIHandlers.Grants.AssignGroup)
	roles.Get("/group-role-assignments", s.APIHandlers.Grants.GroupRoleAssignments)
	roles.Delete("/group-role-assignments/:role/:organization/:group", s.APIHandlers.Grants.UnassignGroup)
	roles.Get("/effective-roles", s.APIHandlers.Grants.EffectiveRoles)

	// Grants
	grants := guarded(e, apiauth.ReadWrite(authorization.PermGrantsRead, authorization.PermGrantsWrite))
	grants.Get("/grants", s.APIHandlers.Grants.ListGrants)
	grants.Get("/grants/:id", s.APIHandlers.Grants.ListGrants)
	grants.Put("/grants", s.APIHandlers.Grants.PutGrant)
	grants.Delete("/grants/:id", s.APIHandlers.Grants.DeleteGrant)

	// Service accounts
	sa := e.Group("/service-accounts", apiauth.ReadWrite(authorization.PermServiceAccountsRead, authorization.PermServiceAccountsWrite))
	sa.Post("/", s.APIHandlers.ServiceAccounts.Create)
	sa.Get("/", s.APIHandlers.ServiceAccounts.List)
	sa.Delete("/:id", s.APIHandlers.ServiceAccounts.Revoke)

	// Delivery config
	if d := s.APIHandlers.Delivery; d != nil {
		delivery := e.Group("/delivery", apiauth.ReadWrite(authorization.PermDeliveryRead, authorization.PermDeliveryWrite))
		delivery.Get("/", d.Get)
		delivery.Put("/", d.Set)
		delivery.Delete("/", d.Delete)
		delivery.Get("/status", d.Status)
		delivery.Post("/test", d.Limit, d.Test)
		delivery.Get("/preview", d.SavedPreview)
		delivery.Post("/preview", d.DraftPreview)
		if d.HasTemplates() {
			delivery.Get("/templates", d.ListTemplates)
			delivery.Get("/templates/:purpose/:locale", d.GetTemplate)
			delivery.Put("/templates/:purpose/:locale", d.SetTemplate)
			delivery.Delete("/templates/:purpose/:locale", d.ResetTemplate)
		}
	}
}

// checkedRoutes registers routes on a router with a check that runs for
// those routes only.
type checkedRoutes struct {
	r     fiber.Router
	check fiber.Handler
}

func guarded(r fiber.Router, check fiber.Handler) checkedRoutes { return checkedRoutes{r, check} }

func (g checkedRoutes) Get(path string, h fiber.Handler)    { g.r.Get(path, g.check, h) }
func (g checkedRoutes) Post(path string, h fiber.Handler)   { g.r.Post(path, g.check, h) }
func (g checkedRoutes) Put(path string, h fiber.Handler)    { g.r.Put(path, g.check, h) }
func (g checkedRoutes) Patch(path string, h fiber.Handler)  { g.r.Patch(path, g.check, h) }
func (g checkedRoutes) Delete(path string, h fiber.Handler) { g.r.Delete(path, g.check, h) }
