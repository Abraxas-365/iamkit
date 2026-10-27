package oauthhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// ProtectedResources serves an environment's protected resources and
// their TTL policy (…/protected-resources, …/protected-resource-policy).
type ProtectedResources struct {
	commands oauth.ProtectedResourceCommands
	queries  oauth.ProtectedResourceQueries
	actor    func(*fiber.Ctx) string
}

func NewProtectedResources(commands oauth.ProtectedResourceCommands, queries oauth.ProtectedResourceQueries, actor func(*fiber.Ctx) string) *ProtectedResources {
	return &ProtectedResources{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *ProtectedResources) WithActor(actor func(*fiber.Ctx) string) *ProtectedResources {
	return &ProtectedResources{commands: h.commands, queries: h.queries, actor: actor}
}

// Register mounts the routes on the environment group r.
func (h *ProtectedResources) Register(r fiber.Router) {
	h.ResourceRoutes(r.Group("/protected-resources"))
	h.PolicyRoutes(r.Group("/protected-resource-policy"))
}

// ResourceRoutes mounts the routes on a /protected-resources group (the
// /api/v1 one carries its permission check).
func (h *ProtectedResources) ResourceRoutes(r fiber.Router) {
	r.Get("/", h.list)
	r.Post("/", h.create)
	r.Get("/:id", h.find)
	r.Get("/:id/impact", h.impact)
	r.Patch("/:id", h.update)
	r.Delete("/:id", h.delete)
}

// PolicyRoutes mounts the routes on a /protected-resource-policy group.
func (h *ProtectedResources) PolicyRoutes(r fiber.Router) {
	r.Get("/", h.policy)
	r.Put("/", h.setPolicy)
}

func (h *ProtectedResources) mutation(c *fiber.Ctx) oauth.Mutation {
	return oauth.Mutation{Environment: env(c), Actor: h.actor(c)}
}

func protectedID(c *fiber.Ctx) (identity.ProtectedResourceID, error) {
	id, err := identity.ParseProtectedResourceID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("protected resource not found")
	}
	return id, nil
}

func (h *ProtectedResources) list(c *fiber.Ctx) error {
	out, err := h.queries.ListProtectedResources(c.UserContext(), env(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ProtectedResources) create(c *fiber.Ctx) error {
	var input oauth.ProtectedResourceCreate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	id, err := h.commands.CreateProtectedResource(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	out, err := h.queries.FindProtectedResource(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *ProtectedResources) find(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindProtectedResource(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// impact returns the live sessions deactivating or deleting the resource
// would end, so the console can warn before either.
func (h *ProtectedResources) impact(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ProtectedResourceImpact(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ProtectedResources) update(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	var input oauth.ProtectedResourceUpdate
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err = h.commands.UpdateProtectedResource(c.UserContext(), h.mutation(c), id, input); err != nil {
		return err
	}
	out, err := h.queries.FindProtectedResource(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ProtectedResources) delete(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	if err = h.commands.DeleteProtectedResource(c.UserContext(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *ProtectedResources) policy(c *fiber.Ctx) error {
	out, err := h.queries.ProtectedResourcePolicy(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *ProtectedResources) setPolicy(c *fiber.Ctx) error {
	var input oauth.ProtectedResourcePolicy
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.SetProtectedResourcePolicy(c.UserContext(), h.mutation(c), input); err != nil {
		return err
	}
	return c.JSON(input)
}
