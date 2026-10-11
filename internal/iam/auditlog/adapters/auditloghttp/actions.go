package auditloghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Actions serves the catalog of registered actions
// (…/audit-logs/actions).
type Actions struct {
	commands auditlog.ActionCommands
	queries  auditlog.ActionQueries
	actor    func(*fiber.Ctx) string
}

func NewActions(commands auditlog.ActionCommands, queries auditlog.ActionQueries, actor func(*fiber.Ctx) string) *Actions {
	return &Actions{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Actions) WithActor(actor func(*fiber.Ctx) string) *Actions {
	return &Actions{commands: h.commands, queries: h.queries, actor: actor}
}

// Register mounts the routes under /audit-logs/actions of r.
func (h *Actions) Register(r fiber.Router) { h.Routes(r.Group("/audit-logs/actions")) }

// Routes mounts the routes on an /audit-logs/actions group (the /api/v1
// one carries its permission check).
func (h *Actions) Routes(r fiber.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/:id", h.Find)
	r.Patch("/:id", h.Update)
	r.Delete("/:id", h.Delete)
}

func action(c *fiber.Ctx) (identity.EnvironmentID, identity.AuditActionID, error) {
	env, err := environment(c)
	if err != nil {
		return env, identity.AuditActionID{}, err
	}
	id, err := identity.ParseAuditActionID(c.Params("id"))
	if err != nil {
		return env, id, auditlog.ErrActionNotFound()
	}
	return env, id, nil
}

func (h *Actions) mutation(c *fiber.Ctx, env identity.EnvironmentID, verb string) auditlog.Mutation {
	return auditlog.Mutation{Environment: env, Actor: h.actor(c), Action: verb}
}

func (h *Actions) List(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListActions(c.UserContext(), env)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Actions) Create(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	var input auditlog.ActionInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.CreateAction(c.UserContext(), h.mutation(c, env, auditlog.AuditActionCreate), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Actions) Find(c *fiber.Ctx) error {
	env, id, err := action(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindAction(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Update changes the description, target types or schema; a change of the
// target types or schemas bumps the version.
func (h *Actions) Update(c *fiber.Ctx) error {
	env, id, err := action(c)
	if err != nil {
		return err
	}
	var input auditlog.ActionUpdate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.UpdateAction(c.UserContext(), h.mutation(c, env, auditlog.AuditActionUpdate), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Delete removes the action; events already emitted keep its name.
func (h *Actions) Delete(c *fiber.Ctx) error {
	env, id, err := action(c)
	if err != nil {
		return err
	}
	if err := h.commands.DeleteAction(c.UserContext(), h.mutation(c, env, auditlog.AuditActionDelete), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
