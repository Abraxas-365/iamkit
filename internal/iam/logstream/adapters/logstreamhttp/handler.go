// Package logstreamhttp serves log streams
// (…/environments/:environment/log-streams, management and /api/v1).
package logstreamhttp

import (
	"strconv"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Handler serves the environment's log streams (operators: every stream,
// organization streams included).
type Handler struct {
	commands logstream.Commands
	queries  logstream.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands logstream.Commands, queries logstream.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Handler) WithActor(actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: h.commands, queries: h.queries, actor: actor}
}

// Register mounts the routes under /log-streams of r.
func (h *Handler) Register(r fiber.Router) { h.Routes(r.Group("/log-streams")) }

// Routes mounts the routes on a /log-streams group (the /api/v1 one
// carries its permission check).
func (h *Handler) Routes(r fiber.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/:stream", h.Find)
	r.Patch("/:stream", h.Update)
	r.Delete("/:stream", h.Delete)
	r.Post("/:stream/test", h.Test)
	r.Post("/:stream/enable", h.Enable)
	r.Post("/:stream/rotate-secret", h.Rotate)
	r.Get("/:stream/deliveries", h.Deliveries)
	r.Post("/:stream/deliveries/:delivery/retry", h.Retry)
}

func scope(c *fiber.Ctx) (logstream.Scope, error) {
	id, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return logstream.Scope{}, errx.Validation("environment must be a valid UUID")
	}
	return logstream.EnvironmentScope(id), nil
}

func stream(c *fiber.Ctx) (logstream.Scope, identity.LogStreamID, error) {
	sc, err := scope(c)
	if err != nil {
		return sc, identity.LogStreamID{}, err
	}
	id, err := identity.ParseLogStreamID(c.Params("stream"))
	if err != nil {
		return sc, id, errx.NotFound("log stream not found")
	}
	return sc, id, nil
}

func (h *Handler) mutation(c *fiber.Ctx, sc logstream.Scope, action string) logstream.Mutation {
	return logstream.Mutation{Scope: sc, Actor: h.actor(c), Action: action}
}

func (h *Handler) List(c *fiber.Ctx) error {
	sc, err := scope(c)
	if err != nil {
		return err
	}
	out, err := h.queries.List(c.UserContext(), sc)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) Create(c *fiber.Ctx) error {
	sc, err := scope(c)
	if err != nil {
		return err
	}
	var input logstream.Create
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.Create(c.UserContext(), h.mutation(c, sc, logstream.ActionCreate), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) Find(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), sc, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	var input logstream.Update
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	if err := h.commands.Update(c.UserContext(), h.mutation(c, sc, logstream.ActionUpdate), id, input); err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), sc, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Enable resumes a stream (clearing its failure): PATCH active=true.
func (h *Handler) Enable(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	active := true
	if err := h.commands.Update(c.UserContext(), h.mutation(c, sc, logstream.ActionUpdate), id, logstream.Update{Active: &active}); err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), sc, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	if err := h.commands.Delete(c.UserContext(), h.mutation(c, sc, logstream.ActionDelete), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) Rotate(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	out, err := h.commands.RotateSecret(c.UserContext(), h.mutation(c, sc, logstream.ActionRotateSecret), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Test sends one synthetic record now and answers with the outcome.
func (h *Handler) Test(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	out, err := h.commands.Test(c.UserContext(), sc, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Deliveries reads the delivery log. Query: status (pending, delivered,
// failed), limit, offset.
func (h *Handler) Deliveries(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListDeliveries(c.UserContext(), sc, id, logstream.DeliveryFilter{Status: c.Query("status")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Retry queues a failed delivery's batch again.
func (h *Handler) Retry(c *fiber.Ctx) error {
	sc, id, err := stream(c)
	if err != nil {
		return err
	}
	delivery, err := strconv.ParseInt(c.Params("delivery"), 10, 64)
	if err != nil || delivery <= 0 {
		return errx.NotFound("failed log stream delivery not found")
	}
	if err := h.commands.RetryDelivery(c.UserContext(), h.mutation(c, sc, logstream.ActionRetryDelivery), id, delivery); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusAccepted)
}
