package eventhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Retention serves an environment's event retention
// (…/environments/:environment/event-retention).
type Retention struct {
	commands event.RetentionCommands
	queries  event.RetentionQueries
	actor    func(*fiber.Ctx) string
	owner    func(*fiber.Ctx) bool
}

// NewRetention: owner reports whether the operator is a workspace owner;
// only owners shorten the retention (it deletes events).
func NewRetention(commands event.RetentionCommands, queries event.RetentionQueries, actor func(*fiber.Ctx) string, owner func(*fiber.Ctx) bool) *Retention {
	return &Retention{commands: commands, queries: queries, actor: actor, owner: owner}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Retention) WithActor(actor func(*fiber.Ctx) string) *Retention {
	return &Retention{commands: h.commands, queries: h.queries, actor: actor, owner: h.owner}
}

// Register mounts GET and PUT /event-retention under an environment router
// (management).
func (h *Retention) Register(e fiber.Router) {
	e.Get("/event-retention", h.Get)
	e.Put("/event-retention", h.Set)
}

// Get answers the effective retention per class, the deployment ceilings
// and the environment's overrides (/api/v1 mounts it with iam:events:read).
func (h *Retention) Get(c *fiber.Ctx) error {
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return errx.Validation("environment must be a valid UUID")
	}
	out, err := h.queries.Retention(c.UserContext(), environment)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Set replaces the overrides: {"security_retention_seconds": n|null,
// "default_retention_seconds": n|null}.
func (h *Retention) Set(c *fiber.Ctx) error {
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return errx.Validation("environment must be a valid UUID")
	}
	var input event.RetentionPolicy
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("security_retention_seconds and default_retention_seconds must be numbers or null")
	}
	m := event.Mutation{Environment: environment, Actor: h.actor(c), Action: c.Method(), Target: c.Path(), Owner: h.owner != nil && h.owner(c)}
	out, err := h.commands.SetRetention(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
