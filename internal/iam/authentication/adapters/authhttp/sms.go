package authhttp

import (
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
)

// SMSHandler serves an environment's SMS provider settings (/sms).
type SMSHandler struct {
	commands authentication.SMSCommands
	queries  authentication.SMSQueries
	actor    func(*fiber.Ctx) string
	limit    fiber.Handler
}

func NewSMSHandler(commands authentication.SMSCommands, queries authentication.SMSQueries, actor func(*fiber.Ctx) string) *SMSHandler {
	return &SMSHandler{commands: commands, queries: queries, actor: actor, limit: limiter.New(limiter.Config{
		Max: TestSendsPerMinute, Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string { return c.Params("environment") + "|" + c.IP() },
		LimitReached: func(*fiber.Ctx) error {
			return errx.TooManyRequests("too many test messages; wait a minute")
		},
	})}
}

// Register mounts the routes under an environment router.
func (h *SMSHandler) Register(e fiber.Router) {
	e.Get("/sms", h.Get)
	e.Put("/sms", h.Set)
	e.Delete("/sms", h.Delete)
	e.Get("/sms/status", h.Status)
	e.Post("/sms/test", h.Limit, h.Test)
}

// Limit is the rate limit of Test.
func (h *SMSHandler) Limit(c *fiber.Ctx) error { return h.limit(c) }

func (h *SMSHandler) mutation(c *fiber.Ctx) authentication.Mutation {
	return authentication.Mutation{Environment: envParam(c), Actor: h.actor(c)}
}

func (h *SMSHandler) Get(c *fiber.Ctx) error {
	out, err := h.queries.SMSConfig(c.UserContext(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *SMSHandler) Set(c *fiber.Ctx) error {
	var input authentication.SMSConfigInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.commands.SetSMSConfig(c.UserContext(), h.mutation(c), input); err != nil {
		return err
	}
	return h.Get(c)
}

func (h *SMSHandler) Delete(c *fiber.Ctx) error {
	if err := h.commands.DeleteSMSConfig(c.UserContext(), h.mutation(c)); err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (h *SMSHandler) Status(c *fiber.Ctx) error {
	out, err := h.queries.SMSStatus(c.UserContext(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Test texts a test message; the response is the attempt, delivered or not.
func (h *SMSHandler) Test(c *fiber.Ctx) error {
	var input authentication.SMSTestInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.TestSMS(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
