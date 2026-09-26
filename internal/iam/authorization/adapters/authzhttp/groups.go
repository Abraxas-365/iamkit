package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

func (h *Grants) AssignGroup(c *fiber.Ctx) error {
	var input authorization.GroupRoleAssignment
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.AssignGroupRole(c.Context(), h.mutation(c), input, false); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Grants) UnassignGroup(c *fiber.Ctx) error {
	role, _ := identity.ParseRoleID(c.Params("role"))
	org, _ := identity.ParseOrganizationID(c.Params("organization"))
	group, _ := identity.ParseGroupID(c.Params("group"))
	input := authorization.GroupRoleAssignment{Role: role, Organization: org, Group: group}
	if err := h.commands.AssignGroupRole(c.Context(), h.mutation(c), input, true); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *Grants) GroupRoleAssignments(c *fiber.Ctx) error {
	role, _ := identity.ParseRoleID(c.Query("role_id"))
	org, _ := identity.ParseOrganizationID(c.Query("organization_id"))
	group, _ := identity.ParseGroupID(c.Query("group_id"))
	resource, _ := identity.ParseResourceID(c.Query("resource_id"))
	filter := authorization.GroupRoleAssignmentFilter{RoleID: role, OrganizationID: org, GroupID: group, ResourceID: resource}
	out, err := h.queries.GroupRoleAssignments(c.Context(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// EffectiveRoles serves GET /effective-roles?organization_id=&user_id=.
func (h *Grants) EffectiveRoles(c *fiber.Ctx) error {
	org, err := identity.ParseOrganizationID(c.Query("organization_id"))
	if err != nil {
		return errx.Validation("organization_id must be a valid UUID")
	}
	user, err := identity.ParseUserID(c.Query("user_id"))
	if err != nil {
		return errx.Validation("user_id must be a valid UUID")
	}
	out, err := h.queries.EffectiveRoles(c.Context(), env(c), org, user)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}
