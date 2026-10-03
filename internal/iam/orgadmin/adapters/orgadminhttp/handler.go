// Package orgadminhttp serves organization administration under
// /api/v1/environments/:environment/organizations/:organization/admin.
package orgadminhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Caller is the authenticated end user: who, in which organization the
// token was issued, and its permissions (zero user for machine tokens).
type Caller struct {
	User         identity.UserID
	Organization identity.OrganizationID
	Permissions  []string
}

type Handler struct {
	commands orgadmin.Commands
	queries  orgadmin.Queries
	caller   func(*fiber.Ctx) Caller
}

func New(commands orgadmin.Commands, queries orgadmin.Queries, caller func(*fiber.Ctx) Caller) *Handler {
	return &Handler{commands: commands, queries: queries, caller: caller}
}

// Register mounts the routes on the group bound to
// /organizations/:organization/admin.
func (h *Handler) Register(r fiber.Router) {
	r.Use(h.Principal)
	r.Get("/", h.organization)
	r.Patch("/", h.updateSettings)
	r.Get("/members", h.members)
	r.Patch("/members/:user", h.updateMember)
	r.Delete("/members/:user", h.removeMember)
	r.Get("/users", h.users)
	r.Post("/users", h.createUser)
	r.Get("/users/:user", h.user)
	r.Patch("/users/:user", h.updateUser)
	r.Post("/users/:user/deactivate", h.deactivate)
	r.Post("/users/:user/reactivate", h.reactivate)
	r.Post("/users/:user/unlock", h.unlock)
	r.Get("/roles", h.roles)
	r.Get("/members/:user/roles", h.roleAssignments)
	r.Post("/role-assignments", h.assign)
	r.Delete("/role-assignments/:user/:role", h.unassign)
	r.Get("/invitations", h.invitations)
	r.Post("/invitations", h.invite)
	r.Post("/invitations/:invitation/resend", h.resend)
	r.Delete("/invitations/:invitation", h.revoke)
	r.Get("/domains", h.domains)
	r.Post("/domains", h.addDomain)
	r.Post("/domains/:domain/verify", h.verifyDomain)
	r.Delete("/domains/:domain", h.deleteDomain)
	r.Get("/connections", h.connections)
	r.Post("/connections", h.createConnection)
	r.Get("/connections/:connection", h.connection)
	r.Patch("/connections/:connection", h.updateConnection)
	r.Delete("/connections/:connection", h.disableConnection)
	r.Post("/connections/:connection/enable", h.enableConnection)
	r.Get("/events", h.events)
	r.Get("/resources", h.resources)
	r.Get("/resource-grants", h.resourceGrants)
	r.Put("/resource-grants", h.putResourceGrant)
	r.Delete("/resource-grants/:grant", h.deleteResourceGrant)
	r.Get("/granted-resources", h.grantedResources)
	r.Get("/branding", h.branding)
	r.Put("/branding", h.saveBranding)
	r.Delete("/branding", h.deleteBranding)
	r.Get("/password-policy", h.passwordPolicy)
	r.Put("/password-policy", h.setPasswordPolicy)
	r.Delete("/password-policy", h.deletePasswordPolicy)
}

type principalKey struct{}

// Principal admits end users whose token was issued in the path's
// organization; each command then checks its own permission.
func (h *Handler) Principal(c *fiber.Ctx) error {
	caller := h.caller(c)
	org, err := identity.ParseOrganizationID(c.Params("organization"))
	if err != nil || caller.User.IsZero() || caller.Organization != org {
		return errx.Forbidden("token not issued in this organization")
	}
	environment, _ := identity.ParseEnvironmentID(c.Params("environment"))
	c.Locals(principalKey{}, orgadmin.Principal{Environment: environment, Organization: org, User: caller.User, Permissions: caller.Permissions})
	return c.Next()
}

func principal(c *fiber.Ctx) orgadmin.Principal {
	p, _ := c.Locals(principalKey{}).(orgadmin.Principal)
	p.Action, p.Target = c.Method(), c.Path()
	return p
}

func userID(c *fiber.Ctx) (identity.UserID, error) {
	id, err := identity.ParseUserID(c.Params("user"))
	if err != nil {
		return id, errx.NotFound("user not found")
	}
	return id, nil
}

func body(c *fiber.Ctx, input any) error {
	if err := c.BodyParser(input); err != nil {
		return errx.Validation("invalid request body")
	}
	return nil
}

func done(c *fiber.Ctx, err error) error {
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) organization(c *fiber.Ctx) error {
	out, err := h.queries.Organization(c.UserContext(), principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) updateSettings(c *fiber.Ctx) error {
	var input orgadmin.Settings
	if err := body(c, &input); err != nil {
		return err
	}
	return done(c, h.commands.UpdateSettings(c.UserContext(), principal(c), input))
}

func (h *Handler) members(c *fiber.Ctx) error {
	var filter organization.MemberFilter
	if v := c.Query("active"); v == "true" || v == "false" {
		active := v == "true"
		filter.Active = &active
	}
	out, err := h.queries.Members(c.UserContext(), principal(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) updateMember(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	var input organization.MemberUpdate
	if err = body(c, &input); err != nil {
		return err
	}
	return done(c, h.commands.UpdateMember(c.UserContext(), principal(c), id, input))
}

func (h *Handler) removeMember(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.RemoveMember(c.UserContext(), principal(c), id))
}

func (h *Handler) users(c *fiber.Ctx) error {
	out, err := h.queries.Users(c.UserContext(), principal(c), user.Filter{State: user.State(c.Query("state"))}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) user(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.User(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) createUser(c *fiber.Ctx) error {
	var input orgadmin.NewUser
	if err := body(c, &input); err != nil {
		return err
	}
	id, err := h.commands.CreateUser(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id})
}

func (h *Handler) updateUser(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	var input orgadmin.UserChange
	if err = body(c, &input); err != nil {
		return err
	}
	return done(c, h.commands.UpdateUser(c.UserContext(), principal(c), id, input))
}

func (h *Handler) setActive(c *fiber.Ctx, active bool) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.SetUserActive(c.UserContext(), principal(c), id, active))
}
func (h *Handler) deactivate(c *fiber.Ctx) error { return h.setActive(c, false) }
func (h *Handler) reactivate(c *fiber.Ctx) error { return h.setActive(c, true) }

func (h *Handler) unlock(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.UnlockUser(c.UserContext(), principal(c), id))
}

func (h *Handler) roles(c *fiber.Ctx) error {
	out, err := h.queries.Roles(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) roleAssignments(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.RoleAssignments(c.UserContext(), principal(c), id, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) assign(c *fiber.Ctx) error {
	var input orgadmin.Assignment
	if err := body(c, &input); err != nil {
		return err
	}
	return done(c, h.commands.AssignRole(c.UserContext(), principal(c), input))
}

func (h *Handler) unassign(c *fiber.Ctx) error {
	id, err := userID(c)
	if err != nil {
		return err
	}
	role, err := identity.ParseRoleID(c.Params("role"))
	if err != nil {
		return errx.NotFound("role not found")
	}
	return done(c, h.commands.UnassignRole(c.UserContext(), principal(c), orgadmin.Assignment{User: id, Role: role}))
}

func (h *Handler) invitations(c *fiber.Ctx) error {
	out, err := h.queries.Invitations(c.UserContext(), principal(c), invitation.Filter{Status: c.Query("status")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) invite(c *fiber.Ctx) error {
	var input invitation.Input
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.Invite(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func invitationID(c *fiber.Ctx) (identity.InvitationID, error) {
	id, err := identity.ParseInvitationID(c.Params("invitation"))
	if err != nil {
		return id, errx.NotFound("invitation not found")
	}
	return id, nil
}

func (h *Handler) resend(c *fiber.Ctx) error {
	id, err := invitationID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.ResendInvitation(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) revoke(c *fiber.Ctx) error {
	id, err := invitationID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.RevokeInvitation(c.UserContext(), principal(c), id))
}

func (h *Handler) domains(c *fiber.Ctx) error {
	out, err := h.queries.Domains(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) addDomain(c *fiber.Ctx) error {
	var input organization.DomainInput
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.AddDomain(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func domainID(c *fiber.Ctx) (identity.DomainID, error) {
	id, err := identity.ParseDomainID(c.Params("domain"))
	if err != nil {
		return id, errx.NotFound("domain not found")
	}
	return id, nil
}

func (h *Handler) verifyDomain(c *fiber.Ctx) error {
	id, err := domainID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.VerifyDomain(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteDomain(c *fiber.Ctx) error {
	id, err := domainID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.DeleteDomain(c.UserContext(), principal(c), id))
}

func (h *Handler) connections(c *fiber.Ctx) error {
	out, err := h.queries.Connections(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func connectionID(c *fiber.Ctx) (identity.ConnectionID, error) {
	id, err := identity.ParseConnectionID(c.Params("connection"))
	if err != nil {
		return id, errx.NotFound("federation connection not found")
	}
	return id, nil
}

func (h *Handler) connection(c *fiber.Ctx) error {
	id, err := connectionID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Connection(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) createConnection(c *fiber.Ctx) error {
	var input federation.ConnectionInput
	if err := body(c, &input); err != nil {
		return err
	}
	id, err := h.commands.CreateConnection(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": id})
}

func (h *Handler) updateConnection(c *fiber.Ctx) error {
	id, err := connectionID(c)
	if err != nil {
		return err
	}
	var input federation.ConnectionUpdate
	if err = body(c, &input); err != nil {
		return err
	}
	return done(c, h.commands.UpdateConnection(c.UserContext(), principal(c), id, input))
}

func (h *Handler) disableConnection(c *fiber.Ctx) error {
	id, err := connectionID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.DisableConnection(c.UserContext(), principal(c), id))
}

func (h *Handler) enableConnection(c *fiber.Ctx) error {
	id, err := connectionID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.EnableConnection(c.UserContext(), principal(c), id))
}

func (h *Handler) events(c *fiber.Ctx) error {
	out, err := h.queries.Events(c.UserContext(), principal(c), orgadmin.EventFilter{Action: c.Query("action")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) resources(c *fiber.Ctx) error {
	out, err := h.queries.Resources(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) resourceGrants(c *fiber.Ctx) error {
	var filter authorization.ResourceGrantFilter
	if raw := c.Query("resource_id"); raw != "" {
		id, err := identity.ParseResourceID(raw)
		if err != nil {
			return errx.Validation("resource_id must be a valid UUID")
		}
		filter.Resource = id
	}
	out, err := h.queries.ResourceGrants(c.UserContext(), principal(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) putResourceGrant(c *fiber.Ctx) error {
	var input authorization.ResourceGrantInput
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.PutResourceGrant(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteResourceGrant(c *fiber.Ctx) error {
	id, err := identity.ParseResourceGrantID(c.Params("grant"))
	if err != nil {
		return errx.NotFound("resource grant not found")
	}
	return done(c, h.commands.DeleteResourceGrant(c.UserContext(), principal(c), id))
}

func (h *Handler) grantedResources(c *fiber.Ctx) error {
	out, err := h.queries.GrantedResources(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
