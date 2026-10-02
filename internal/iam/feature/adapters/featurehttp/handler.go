// Package featurehttp serves feature flags under
// /management/v1/environments/:environment/features.
package featurehttp

import (
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands feature.Commands
	queries  feature.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands feature.Commands, queries feature.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}

func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Register mounts the routes under an environment router.
func (h *Handler) Register(e fiber.Router) {
	e.Get("/features", h.list)
	e.Get("/features/:feature", h.find)
	e.Put("/features/:feature", h.set)
	e.Delete("/features/:feature", h.reset)
}

func (h *Handler) mutation(c *fiber.Ctx) feature.Mutation {
	return feature.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}

func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.queries.List(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) find(c *fiber.Ctx) error {
	out, err := h.queries.Find(c.UserContext(), env(c), c.Params("feature"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) set(c *fiber.Ctx) error {
	var input feature.Set
	if err := c.BodyParser(&input); err != nil {
		return feature.Set{}.Validate()
	}
	out, err := h.commands.Set(c.UserContext(), h.mutation(c), c.Params("feature"), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) reset(c *fiber.Ctx) error {
	out, err := h.commands.Reset(c.UserContext(), h.mutation(c), c.Params("feature"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}
