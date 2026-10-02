package hostedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// registerTexts serves the custom sign-in texts: per language for the
// environment, a client or an organization, the catalog of texts that can
// be customized, and a preview with unsaved texts.
func (h *Handler) registerTexts(e fiber.Router) {
	if h.texts.commands == nil || h.texts.queries == nil {
		return
	}
	e.Get("/login-settings/texts", h.listTexts)
	e.Get("/login-settings/texts/catalog", textCatalog)
	e.Post("/login-settings/texts/preview", h.textsPreview)
	for _, prefix := range []string{"/login-settings", "/login-settings/clients/:client", "/login-settings/organizations/:organization"} {
		e.Get(prefix+"/texts/:locale", h.showTexts)
		e.Put(prefix+"/texts/:locale", h.saveTexts)
		e.Delete(prefix+"/texts/:locale", h.deleteTexts)
	}
}

// textScope is the scope named by the path (:client or :organization).
func textScope(c *fiber.Ctx) (hosted.TextScope, error) {
	var scope hosted.TextScope
	if c.Params("client") != "" {
		id, err := client(c)
		if err != nil {
			return scope, err
		}
		scope.Client = id
	}
	if c.Params("organization") != "" {
		id, err := organization(c)
		if err != nil {
			return scope, err
		}
		scope.Organization = id
	}
	return scope, nil
}

// textCatalog lists the customizable texts of ?locale= (default English)
// with their catalog wording, placeholders and length limits.
func textCatalog(c *fiber.Ctx) error {
	locale := c.Query("locale", i18n.Default)
	code, err := hosted.Language(locale, "locale")
	if err != nil {
		return err
	}
	if code == "" {
		code = i18n.Default
	}
	return c.JSON(fiber.Map{"locale": code, "items": hosted.TextCatalog(code)})
}

func (h *Handler) listTexts(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	out, err := h.texts.queries.ListTexts(c.UserContext(), env, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// showTexts is a scope's custom texts in :locale (texts empty when none).
func (h *Handler) showTexts(c *fiber.Ctx) error {
	env, _ := identity.ParseEnvironmentID(c.Params("environment"))
	scope, err := textScope(c)
	if err != nil {
		return err
	}
	out, err := h.texts.queries.Texts(c.UserContext(), env, scope, c.Params("locale"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// saveTexts replaces a scope's custom texts in :locale with the body's
// {"texts": {key: message}}.
func (h *Handler) saveTexts(c *fiber.Ctx) error {
	scope, err := textScope(c)
	if err != nil {
		return err
	}
	var input struct {
		Texts map[string]string `json:"texts"`
	}
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	texts := hosted.Texts{Locale: c.Params("locale"), Messages: input.Texts}
	if !scope.Client.IsZero() {
		texts.Client = &scope.Client
	}
	if !scope.Organization.IsZero() {
		texts.Organization = &scope.Organization
	}
	out, err := h.texts.commands.SaveTexts(c.UserContext(), h.mutation(c), texts)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteTexts(c *fiber.Ctx) error {
	scope, err := textScope(c)
	if err != nil {
		return err
	}
	if err = h.texts.commands.DeleteTexts(c.UserContext(), h.mutation(c), scope, c.Params("locale")); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
