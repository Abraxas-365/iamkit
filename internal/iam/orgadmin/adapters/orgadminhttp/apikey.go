package orgadminhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/apikey"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

func keyID(c *fiber.Ctx) (identity.APIKeyID, error) {
	id, err := identity.ParseAPIKeyID(c.Params("key"))
	if err != nil {
		return id, errx.NotFound("API key not found")
	}
	return id, nil
}

// KeyFilter reads the listing filters every API key surface shares
// (owner_type, organization_id, user_id, resource_id, state); malformed IDs
// match nothing rather than everything.
func KeyFilter(c *fiber.Ctx) (apikey.Filter, error) {
	f := apikey.Filter{OwnerType: apikey.OwnerKind(c.Query("owner_type")), State: c.Query("state")}
	var err error
	if v := c.Query("organization_id"); v != "" {
		if f.Organization, err = identity.ParseOrganizationID(v); err != nil {
			return f, errx.Validation("organization_id must be a valid UUID")
		}
	}
	if v := c.Query("user_id"); v != "" {
		if f.User, err = identity.ParseUserID(v); err != nil {
			return f, errx.Validation("user_id must be a valid UUID")
		}
	}
	if v := c.Query("resource_id"); v != "" {
		if f.Resource, err = identity.ParseResourceID(v); err != nil {
			return f, errx.Validation("resource_id must be a valid UUID")
		}
	}
	return f, nil
}

func (h *Handler) apiKeys(c *fiber.Ctx) error {
	filter, err := KeyFilter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.APIKeys(c.UserContext(), principal(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) apiKeyOptions(c *fiber.Ctx) error {
	out, err := h.queries.APIKeyOptions(c.UserContext(), principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) apiKey(c *fiber.Ctx) error {
	id, err := keyID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.APIKey(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) createAPIKey(c *fiber.Ctx) error {
	var input apikey.NewAPIKey
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.CreateAPIKey(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) revokeAPIKey(c *fiber.Ctx) error {
	id, err := keyID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.RevokeAPIKey(c.UserContext(), principal(c), id))
}
