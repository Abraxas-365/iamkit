package mgmthttp

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

const sessionCookie = "__Host-iamkit-operator"

type Handler struct {
	auth     management.ManagementAuthenticator
	sessions management.SessionCommands
	commands management.ControlCommands
	queries  management.ControlQueries
}

func New(auth management.ManagementAuthenticator, sessions management.SessionCommands, commands management.ControlCommands, queries management.ControlQueries) *Handler {
	return &Handler{auth, sessions, commands, queries}
}
func Principal(c *fiber.Ctx) management.Principal { return c.Locals("operator").(management.Principal) }
func OperatorID(c *fiber.Ctx) string              { return Principal(c).OperatorID }

// Authenticate resolves a Principal from either a Bearer ik_mgmt_ key or a session cookie.
func (h *Handler) Authenticate(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")

	// Try Bearer token first (existing API clients / SDK).
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.HasPrefix(parts[1], "ik_mgmt_") {
		p, err := h.auth.Authenticate(c.Context(), parts[1])
		if err != nil {
			return errx.Unauthorized("management credential required")
		}
		c.Locals("operator", p)
		return c.Next()
	}

	// Try session cookie (dashboard / browser).
	cookie := c.Cookies(sessionCookie)
	if cookie != "" {
		if c.Method() != fiber.MethodGet && c.Method() != fiber.MethodHead {
			if err := requireConsoleRequest(c); err != nil {
				return err
			}
		}
		p, err := h.auth.AuthenticateSession(c.Context(), cookie)
		if err != nil {
			return errx.Unauthorized("management credential required")
		}
		c.Locals("operator", p)
		return c.Next()
	}

	return errx.Unauthorized("management credential required")
}
func requireWrite(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet && !Principal(c).CanWrite() {
		return errx.Forbidden("insufficient permissions")
	}
	return c.Next()
}
func (h *Handler) Environment(c *fiber.Ctx) error {
	if c.Method() != fiber.MethodGet && !Principal(c).CanWrite() {
		return errx.Forbidden("insufficient permissions")
	}
	id := c.Params("environment")
	if _, err := uuid.Parse(id); err != nil {
		return errx.NotFound("resource not found")
	}
	if !h.auth.EnvironmentAllowed(c.Context(), Principal(c), id) {
		return errx.NotFound("resource not found")
	}
	return c.Next()
}
func (h *Handler) Register(r fiber.Router) {
	r.Get("/me", func(c *fiber.Ctx) error { return c.JSON(Principal(c)) })
	r.Post("/keys", h.createKey)
	r.Get("/keys", h.keys)
	r.Delete("/keys/:id", h.revokeKey)
	r.Post("/operators", h.delegate)
	r.Get("/operators", h.operators)
	r.Delete("/operators/:id", h.disable)
	r.Post("/projects", requireWrite, h.createProject)
	r.Get("/projects", h.projects)
	r.Post("/projects/:project/environments", requireWrite, h.createEnvironment)
	r.Get("/projects/:project/environments", h.environments)
	r.Post("/password", h.setPassword)
	r.Delete("/sessions/current", h.logout)
}

// A custom header forces cross-origin browser requests to preflight. Management
// routes must not enable credentialed cross-origin access for untrusted origins.
func requireConsoleRequest(c *fiber.Ctx) error {
	if c.Get("X-IAMKit-Console") != "1" || c.Get("Sec-Fetch-Site") == "cross-site" {
		return errx.Forbidden("same-origin console request required")
	}
	return nil
}

// Login is registered outside the Authenticate middleware — it is unauthenticated.
func (h *Handler) Login(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	if err := requireConsoleRequest(c); err != nil {
		return err
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	raw, p, err := h.sessions.Login(c.Context(), input.Email, input.Password)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookie,
		Value:    raw,
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		MaxAge:   3600, // 1 hour, matches session expiry
	})
	c.Set("Cache-Control", "no-store")
	return c.JSON(fiber.Map{
		"operator_id":  p.OperatorID,
		"workspace_id": p.WorkspaceID,
		"role":         p.Role,
	})
}
func (h *Handler) logout(c *fiber.Ctx) error {
	cookie := c.Cookies(sessionCookie)
	if cookie != "" {
		if err := h.sessions.Logout(c.Context(), cookie); err != nil {
			return err
		}
	}
	c.Cookie(&fiber.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
		SameSite: "Strict",
		MaxAge:   -1,
	})
	return c.SendStatus(204)
}
func (h *Handler) setPassword(c *fiber.Ctx) error {
	var input struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.sessions.SetPassword(c.Context(), Principal(c), input.Password); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) createKey(c *fiber.Ctx) error {
	var input struct {
		ExpiresIn *string `json:"expires_in"`
	}
	// Body is optional — empty body means default TTL.
	c.BodyParser(&input)
	out, err := h.commands.CreateKey(c.Context(), Principal(c), input.ExpiresIn)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}
func (h *Handler) keys(c *fiber.Ctx) error {
	out, err := h.queries.Keys(c.Context(), Principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) revokeKey(c *fiber.Ctx) error {
	if err := h.commands.RevokeKey(c.Context(), Principal(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) delegate(c *fiber.Ctx) error {
	var input struct {
		Email     string  `json:"email"`
		Role      string  `json:"role"`
		ExpiresIn *string `json:"expires_in"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Delegate(c.Context(), Principal(c), input.Email, input.Role, input.ExpiresIn)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}
func (h *Handler) disable(c *fiber.Ctx) error {
	if err := h.commands.DisableOperator(c.Context(), Principal(c), c.Params("id")); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) operators(c *fiber.Ctx) error {
	out, err := h.queries.Operators(c.Context(), Principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) createProject(c *fiber.Ctx) error {
	var input struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.CreateProject(c.Context(), Principal(c), input.Name)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) projects(c *fiber.Ctx) error {
	out, err := h.queries.Projects(c.Context(), Principal(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Handler) createEnvironment(c *fiber.Ctx) error {
	var input struct {
		Name string `json:"name"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.CreateEnvironment(c.Context(), Principal(c), c.Params("project"), input.Name)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) environments(c *fiber.Ctx) error {
	out, err := h.queries.Environments(c.Context(), Principal(c), c.Params("project"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
