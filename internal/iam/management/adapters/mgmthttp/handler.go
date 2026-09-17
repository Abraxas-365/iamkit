package mgmthttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"strings"
)

type Handler struct {
	auth     management.ManagementAuthenticator
	commands management.ControlCommands
	queries  management.ControlQueries
}

func New(auth management.ManagementAuthenticator, commands management.ControlCommands, queries management.ControlQueries) *Handler {
	return &Handler{auth, commands, queries}
}
func Principal(c *fiber.Ctx) management.Principal { return c.Locals("operator").(management.Principal) }
func OperatorID(c *fiber.Ctx) string              { return Principal(c).OperatorID }
func (h *Handler) Authenticate(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store")
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return errx.Unauthorized("management credential required")
	}
	p, err := h.auth.Authenticate(c.Context(), parts[1])
	if err != nil {
		return errx.Unauthorized("management credential required")
	}
	c.Locals("operator", p)
	return c.Next()
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
	r.Delete("/operators/:id", h.disable)
	r.Post("/projects", requireWrite, h.createProject)
	r.Get("/projects", h.projects)
	r.Post("/projects/:project/environments", requireWrite, h.createEnvironment)
	r.Get("/projects/:project/environments", h.environments)
}
func (h *Handler) createKey(c *fiber.Ctx) error {
	out, err := h.commands.CreateKey(c.Context(), Principal(c))
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
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Delegate(c.Context(), Principal(c), input.Email, input.Role)
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
