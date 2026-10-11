package orgadminhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/orgadmin"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// directories lists the organization's SCIM credentials and the SCIM base URL.
func (h *Handler) directories(c *fiber.Ctx) error {
	out, err := h.queries.Directories(c.UserContext(), principal(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// createDirectory answers 201 with the credential; its secret is shown once.
func (h *Handler) createDirectory(c *fiber.Ctx) error {
	var input orgadmin.NewDirectory
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.IssueDirectory(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) revokeDirectory(c *fiber.Ctx) error {
	id, err := identity.ParseCredentialID(c.Params("credential"))
	if err != nil {
		return errx.NotFound("directory credential not found")
	}
	return done(c, h.commands.RevokeDirectory(c.UserContext(), principal(c), id))
}
