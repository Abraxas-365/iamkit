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
	commands authentication.DeliveryConfigCommands
	queries  authentication.DeliveryConfigQueries
	actor    func(*fiber.Ctx) string
	limit    fiber.Handler
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
}

func envParam(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Limit is the rate limit of Test, for routers that mount it themselves.
func (h *DeliveryHandler) Limit(c *fiber.Ctx) error { return h.limit(c) }

func (h *DeliveryHandler) Get(c *fiber.Ctx) error {
	cfg, err := h.queries.DeliveryConfig(c.Context(), envParam(c))
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
	if err := h.commands.SetDeliveryConfig(c.Context(), h.mutation(c), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *DeliveryHandler) Delete(c *fiber.Ctx) error {
	if err := h.commands.DeleteDeliveryConfig(c.Context(), h.mutation(c)); err != nil {
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
	out, err := h.queries.DeliveryStatus(c.Context(), envParam(c))
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
	out, err := h.commands.TestDelivery(c.Context(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
