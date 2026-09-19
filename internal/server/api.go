package server

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/server/apiauth"
	"github.com/gofiber/fiber/v2"
)

// apiRoutes registers the /api/v1/* route group, which accepts JWT tokens
// (from machine-token or user login) and enforces scoped IAM permissions.
// Handlers are the same as management but wired with JWT-based auth.
func (s *Server) apiRoutes(app *fiber.App, rateLimit int) {
	if s.API == nil {
		return
	}
	api := app.Group("/api/v1", s.API.Authenticate, rateLimiter(rateLimit))
	e := api.Group("/environments/:environment")

	// Users
	users := e.Group("/users", apiauth.ReadWrite(authorization.PermUsersRead, authorization.PermUsersWrite))
	users.Post("/", s.APIHandlers.Users.Create)
	users.Get("/", s.APIHandlers.Users.List)
	users.Get("/:id", s.APIHandlers.Users.Find)
	users.Patch("/:id", s.APIHandlers.Users.Update)
	users.Delete("/:id", s.APIHandlers.Users.Suspend)

	// Organizations
	orgs := e.Group("/organizations", apiauth.ReadWrite(authorization.PermOrgsRead, authorization.PermOrgsWrite))
	orgs.Post("/", s.APIHandlers.Organizations.Create)
	orgs.Get("/", s.APIHandlers.Organizations.List)
	orgs.Get("/:id", s.APIHandlers.Organizations.Find)
	orgs.Patch("/:id", s.APIHandlers.Organizations.Update)

	// Members
	members := e.Group("", apiauth.ReadWrite(authorization.PermMembersRead, authorization.PermMembersWrite))
	members.Post("/memberships", s.APIHandlers.Organizations.AddMember)
	members.Get("/organizations/:organization/members", s.APIHandlers.Organizations.Members)
	members.Delete("/organizations/:organization/members/:user", s.APIHandlers.Organizations.RemoveMember)

	// Org structure (follows org membership domain)
	structure := e.Group("/organizations/:organization", apiauth.ReadWrite(authorization.PermMembersRead, authorization.PermMembersWrite), s.APIHandlers.Structure.Check)
	s.APIHandlers.Structure.RegisterViews(structure)
	s.APIHandlers.Structure.RegisterMutations(structure)

	// Applications
	apps := e.Group("/applications", apiauth.ReadWrite(authorization.PermAppsRead, authorization.PermAppsWrite))
	apps.Post("/", s.APIHandlers.Applications.Create)
	apps.Get("/", s.APIHandlers.Applications.List)
	apps.Get("/:id", s.APIHandlers.Applications.Find)
	apps.Patch("/:id", s.APIHandlers.Applications.Update)

	// Resources
	res := e.Group("", apiauth.ReadWrite(authorization.PermResourcesRead, authorization.PermResourcesWrite))
	res.Post("/resources", s.APIHandlers.Authorization.Create)
	res.Get("/resources", s.APIHandlers.Authorization.List)
	res.Get("/resources/:id", s.APIHandlers.Authorization.Find)
	res.Put("/resources/:id", s.APIHandlers.Authorization.Update)
	res.Post("/application-resources", s.APIHandlers.Authorization.Link)
	res.Delete("/application-resources/:application/:resource", s.APIHandlers.Authorization.Unlink)
	res.Get("/applications/:application/resources", s.APIHandlers.Authorization.ListByApplication)

	// Roles
	roles := e.Group("", apiauth.ReadWrite(authorization.PermRolesRead, authorization.PermRolesWrite))
	roles.Get("/roles", s.APIHandlers.Grants.ListRoles)
	roles.Get("/roles/:id", s.APIHandlers.Grants.ListRoles)
	roles.Post("/roles", s.APIHandlers.Grants.SaveRole)
	roles.Put("/roles/:id", s.APIHandlers.Grants.SaveRole)
	roles.Delete("/roles/:id", s.APIHandlers.Grants.DeleteRole)
	roles.Post("/role-assignments", s.APIHandlers.Grants.Assign)
	roles.Get("/role-assignments", s.APIHandlers.Grants.RoleAssignments)
	roles.Delete("/role-assignments/:role/:organization/:user", s.APIHandlers.Grants.Unassign)

	// Grants
	grants := e.Group("", apiauth.ReadWrite(authorization.PermGrantsRead, authorization.PermGrantsWrite))
	grants.Get("/grants", s.APIHandlers.Grants.ListGrants)
	grants.Get("/grants/:id", s.APIHandlers.Grants.ListGrants)
	grants.Put("/grants", s.APIHandlers.Grants.PutGrant)
	grants.Delete("/grants/:id", s.APIHandlers.Grants.DeleteGrant)

	// Service accounts
	sa := e.Group("/service-accounts", apiauth.ReadWrite(authorization.PermServiceAccountsRead, authorization.PermServiceAccountsWrite))
	sa.Post("/", s.APIHandlers.ServiceAccounts.Create)
	sa.Get("/", s.APIHandlers.ServiceAccounts.List)
	sa.Delete("/:id", s.APIHandlers.ServiceAccounts.Revoke)
}
