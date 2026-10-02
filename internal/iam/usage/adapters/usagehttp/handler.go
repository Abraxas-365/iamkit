// Package usagehttp serves limits and usage
// (…/environments/:environment/limits, …/usage) and meters API requests.
package usagehttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands usage.Commands
	queries  usage.Queries
	actor    func(*fiber.Ctx) string
	owner    func(*fiber.Ctx) bool
}

// New: owner reports whether the operator is a workspace owner.
func New(commands usage.Commands, queries usage.Queries, actor func(*fiber.Ctx) string, owner func(*fiber.Ctx) bool) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor, owner: owner}
}

func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Register mounts the management routes under an environment router.
func (h *Handler) Register(e fiber.Router) {
	e.Get("/limits", h.Limits)
	e.Put("/limits", h.setLimits)
	e.Get("/usage", h.Usage)
}

// Limits answers the deployment caps, the environment's own limits and
// the effective values.
func (h *Handler) Limits(c *fiber.Ctx) error {
	out, err := h.queries.Limits(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) setLimits(c *fiber.Ctx) error {
	var input usage.Set
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("limits must be an object of limit names to numbers or null")
	}
	m := usage.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path(), Owner: h.owner != nil && h.owner(c)}
	out, err := h.commands.SetLimits(c.UserContext(), m, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Usage reports daily usage. Query: days (1–366, default 30).
func (h *Handler) Usage(c *fiber.Ctx) error {
	out, err := h.queries.Report(c.UserContext(), env(c), c.QueryInt("days", 30))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Meter limits and counts API requests per environment; it must sit where
// :environment is bound. Unknown environments pass (later checks refuse).
func Meter(commands usage.Commands) fiber.Handler {
	return func(c *fiber.Ctx) error {
		environment, err := identity.ParseEnvironmentID(c.Params("environment"))
		if err != nil {
			return c.Next()
		}
		if err = commands.Admit(c.UserContext(), environment, usage.LimitRequests); err != nil {
			return err
		}
		commands.Count(c.UserContext(), environment, usage.MetricRequests, 1)
		return c.Next()
	}
}
