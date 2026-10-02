// Package signinghttp serves environment signing-key rotation under
// /management/v1/environments/:environment/signing-keys.
package signinghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/signing"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands signing.Commands
	queries  signing.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands signing.Commands, queries signing.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}

func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Register mounts the routes under an environment router.
func (h *Handler) Register(e fiber.Router) {
	e.Get("/signing-keys", h.list)
	e.Post("/signing-keys", h.create)
	e.Get("/signing-keys/:kid", h.find)
	e.Post("/signing-keys/:kid/activate", h.activate)
	e.Post("/signing-keys/:kid/retire", h.retire)
}

func (h *Handler) mutation(c *fiber.Ctx) signing.Mutation {
	return signing.Mutation{Environment: env(c), Actor: h.actor(c)}
}

func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.queries.List(c.UserContext(), env(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) find(c *fiber.Ctx) error {
	out, err := h.queries.Find(c.UserContext(), env(c), c.Params("kid"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) create(c *fiber.Ctx) error {
	out, err := h.commands.Create(c.UserContext(), h.mutation(c))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) activate(c *fiber.Ctx) error {
	out, err := h.commands.Activate(c.UserContext(), h.mutation(c), c.Params("kid"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) retire(c *fiber.Ctx) error {
	var input signing.Retire
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&input); err != nil {
			return errx.Validation("invalid request")
		}
	}
	out, err := h.commands.Retire(c.UserContext(), h.mutation(c), c.Params("kid"), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
