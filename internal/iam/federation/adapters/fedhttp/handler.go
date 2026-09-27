package fedhttp

import (
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands federation.Commands
	queries  federation.Queries
	flows    federation.Flows
	actor    func(*fiber.Ctx) string
	respond  func(*fiber.Ctx, authentication.Result) error
	hosted   func(*fiber.Ctx, federation.Outcome, error) error
}

func New(commands federation.Commands, queries federation.Queries, flows federation.Flows, actor func(*fiber.Ctx) string, respond func(*fiber.Ctx, authentication.Result) error) *Handler {
	return &Handler{commands: commands, queries: queries, flows: flows, actor: actor, respond: respond}
}

// Continue sets where callbacks of hosted login starts resume. The hosted
// login module is assembled after federation, so the composition root sets
// it once both exist.
func (h *Handler) Continue(hosted func(*fiber.Ctx, federation.Outcome, error) error) {
	h.hosted = hosted
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) Register(e fiber.Router) {
	e.Post("/federation-connections", h.create)
	e.Get("/federation-connections", h.list)
	e.Get("/federation-connections/:id", h.find)
	e.Patch("/federation-connections/:id", h.update)
	e.Get("/federation-connections/:id/identities", h.identities)
	e.Delete("/federation-connections/:id", h.disable)
	e.Post("/external-identities", h.link)
	e.Delete("/external-identities/:connection/:user", h.unlink)
}
func (h *Handler) mutation(c *fiber.Ctx) federation.Mutation {
	return federation.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}
func (h *Handler) create(c *fiber.Ctx) error {
	var input federation.ConnectionInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.Create(c.Context(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) update(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.NotFound("federation connection not found")
	}
	var input federation.ConnectionUpdate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.Update(c.Context(), h.mutation(c), id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) link(c *fiber.Ctx) error {
	var input struct {
		Connection identity.ConnectionID `json:"connection_id"`
		User       identity.UserID       `json:"user_id"`
		Subject    string                `json:"subject"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.Link(c.Context(), h.mutation(c), input.Connection, input.User, input.Subject); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) disable(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid connection id")
	}
	if err := h.commands.Disable(c.Context(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) list(c *fiber.Ctx) error {
	var filter federation.ConnectionFilter
	if raw := c.Query("organization_id"); raw != "" {
		org, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return errx.Validation("organization_id must be a valid UUID")
		}
		filter.Organization = org
	}
	out, err := h.queries.List(c.Context(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) find(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.NotFound("connection not found")
	}
	out, err := h.queries.Connection(c.Context(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) identities(c *fiber.Ctx) error {
	id, err := identity.ParseConnectionID(c.Params("id"))
	if err != nil {
		return errx.NotFound("connection not found")
	}
	out, err := h.queries.Identities(c.Context(), env(c), id, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) unlink(c *fiber.Ctx) error {
	conn, err := identity.ParseConnectionID(c.Params("connection"))
	if err != nil {
		return errx.Validation("invalid connection id")
	}
	user, err := identity.ParseUserID(c.Params("user"))
	if err != nil {
		return errx.Validation("invalid user id")
	}
	if err := h.commands.Unlink(c.Context(), h.mutation(c), conn, user); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Start(c *fiber.Ctx) error {
	var input struct {
		authentication.Context
		Connection identity.ConnectionID `json:"connection_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.flows.Start(c.Context(), input.Context, input.Connection)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-federation", Value: out.Binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.FederationStateTTL.Seconds())})
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{"authorization_url": out.URL})
}
func (h *Handler) Callback(c *fiber.Ctx) error {
	out, err := h.flows.Callback(c.Context(), c.Query("code"), c.Query("state"), c.Cookies("__Host-iamkit-federation"))
	if out.Hosted() && h.hosted != nil {
		c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-federation", Value: "", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: -1})
		return h.hosted(c, out, err)
	}
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: "__Host-iamkit-federation", Value: "", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: -1})
	return h.respond(c, authentication.Result{Issued: out.Issued, MFA: out.MFA})
}

// CallbackForm serves Apple's form_post callback. The binding cookies are
// SameSite=Lax, so a cross-site POST does not carry them; a 303 to the GET
// callback (a top-level navigation) does.
func (h *Handler) CallbackForm(c *fiber.Ctx) error {
	q := url.Values{}
	for _, key := range []string{"code", "state", "error"} {
		if v := c.FormValue(key); v != "" {
			q.Set(key, v)
		}
	}
	c.Set("Cache-Control", "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	return c.Redirect("/identity/v1/federation/callback?"+q.Encode(), fiber.StatusSeeOther)
}

// Discover serves POST /identity/v1/discover: which login method an email
// should use. The answer depends only on the email's domain.
func (h *Handler) Discover(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Email       string                 `json:"email"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.flows.Discover(c.Context(), input.Environment, input.Email)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}
