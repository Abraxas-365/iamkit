package authhttp

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// TestSendsPerMinute bounds test deliveries per environment and client
// address: each one makes IAMKit call the webhook and send an email.
const TestSendsPerMinute = 5

type DeliveryHandler struct {
	commands  authentication.DeliveryConfigCommands
	queries   authentication.DeliveryConfigQueries
	templates templatePorts
	actor     func(*fiber.Ctx) string
	limit     fiber.Handler
}

type templatePorts struct {
	commands authentication.TemplateCommands
	queries  authentication.TemplateQueries
}

// Templates serves email wording routes (/delivery/templates) too.
func (h *DeliveryHandler) Templates(commands authentication.TemplateCommands, queries authentication.TemplateQueries) *DeliveryHandler {
	h.templates = templatePorts{commands, queries}
	return h
}

func NewDeliveryHandler(commands authentication.DeliveryConfigCommands, queries authentication.DeliveryConfigQueries, actor func(*fiber.Ctx) string) *DeliveryHandler {
	return &DeliveryHandler{commands: commands, queries: queries, actor: actor, limit: limiter.New(limiter.Config{
		Max: TestSendsPerMinute, Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string { return c.Params("environment") + "|" + c.IP() },
		LimitReached: func(*fiber.Ctx) error {
			return errx.TooManyRequests("too many test deliveries; wait a minute")
		},
	})}
}

func (h *DeliveryHandler) Register(e fiber.Router) {
	e.Get("/delivery", h.Get)
	e.Put("/delivery", h.Set)
	e.Delete("/delivery", h.Delete)
	e.Get("/delivery/status", h.Status)
	e.Post("/delivery/test", h.Limit, h.Test)
	e.Get("/delivery/preview", h.SavedPreview)
	// A draft preview changes nothing; POST only carries the draft wording.
	e.Post("/delivery/preview", h.DraftPreview)
	if h.templates.queries != nil {
		e.Get("/delivery/templates", h.ListTemplates)
		e.Get("/delivery/templates/:purpose/:locale", h.GetTemplate)
		e.Put("/delivery/templates/:purpose/:locale", h.SetTemplate)
		e.Delete("/delivery/templates/:purpose/:locale", h.ResetTemplate)
	}
}

// HasTemplates reports whether the template routes are served.
func (h *DeliveryHandler) HasTemplates() bool { return h.templates.queries != nil }

func templateKey(c *fiber.Ctx) authentication.TemplateKey {
	return authentication.TemplateKey{Purpose: c.Params("purpose"), Locale: c.Params("locale")}
}

func (h *DeliveryHandler) ListTemplates(c *fiber.Ctx) error {
	out, err := h.templates.queries.ListTemplates(c.UserContext(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *DeliveryHandler) GetTemplate(c *fiber.Ctx) error {
	out, err := h.templates.queries.Template(c.UserContext(), envParam(c), templateKey(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// SetTemplate saves the wording and returns the template as GET does.
func (h *DeliveryHandler) SetTemplate(c *fiber.Ctx) error {
	var input authentication.Copy
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.templates.commands.SetTemplate(c.UserContext(), h.mutation(c), templateKey(c), input); err != nil {
		return err
	}
	return h.GetTemplate(c)
}

func (h *DeliveryHandler) ResetTemplate(c *fiber.Ctx) error {
	if err := h.templates.commands.ResetTemplate(c.UserContext(), h.mutation(c), templateKey(c)); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// SavedPreview renders a sample email with the saved branding and wording.
func (h *DeliveryHandler) SavedPreview(c *fiber.Ctx) error {
	out, err := h.queries.Preview(c.UserContext(), envParam(c), authentication.PreviewInput{Purpose: c.Query("purpose"), Locale: c.Query("locale")})
	if err != nil {
		return err
	}
	return previewFormat(c, out)
}

// DraftPreview renders a sample email with unsaved wording.
func (h *DeliveryHandler) DraftPreview(c *fiber.Ctx) error {
	var input authentication.PreviewInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.queries.Preview(c.UserContext(), envParam(c), input)
	if err != nil {
		return err
	}
	return previewFormat(c, out)
}

// previewCSP lets a preview document show its inline styles and https
// images, nothing else; it is meant for a sandboxed iframe.
const previewCSP = "default-src 'none'; img-src https: data:; style-src 'unsafe-inline'; frame-ancestors 'self'"

// previewFormat writes the preview as JSON (default), the HTML document,
// or the plain-text part (?format=).
func previewFormat(c *fiber.Ctx, p authentication.Preview) error {
	switch c.Query("format") {
	case "", "json":
		return c.JSON(p)
	case "html":
		c.Set(fiber.HeaderContentSecurityPolicy, previewCSP)
		c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
		c.Type("html", "utf-8")
		return c.SendString(p.HTML)
	case "text":
		c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
		c.Type("txt", "utf-8")
		return c.SendString(p.Text)
	}
	return errx.Validation("format must be one of json, html, text")
}

func envParam(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Limit is the rate limit of Test, for routers that mount it themselves.
func (h *DeliveryHandler) Limit(c *fiber.Ctx) error { return h.limit(c) }

func (h *DeliveryHandler) Get(c *fiber.Ctx) error {
	cfg, err := h.queries.DeliveryConfig(c.UserContext(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(cfg)
}

func (h *DeliveryHandler) Set(c *fiber.Ctx) error {
	var input authentication.DeliveryConfigInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.SetDeliveryConfig(c.UserContext(), h.mutation(c), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *DeliveryHandler) Delete(c *fiber.Ctx) error {
	if err := h.commands.DeleteDeliveryConfig(c.UserContext(), h.mutation(c)); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// mutation attributes a change; the service sets the action and target.
func (h *DeliveryHandler) mutation(c *fiber.Ctx) authentication.Mutation {
	return authentication.Mutation{Environment: envParam(c), Actor: h.actor(c)}
}

// Status reports the effective webhook source and recent delivery activity.
func (h *DeliveryHandler) Status(c *fiber.Ctx) error {
	out, err := h.queries.DeliveryStatus(c.UserContext(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Test sends a test message; the response is the attempt, delivered or not.
func (h *DeliveryHandler) Test(c *fiber.Ctx) error {
	var input authentication.TestInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.TestDelivery(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
