package eventhttp

import (
	"strconv"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Subscriptions serves event webhook subscriptions
// (…/environments/:environment/webhooks).
type Subscriptions struct {
	commands event.SubscriptionCommands
	queries  event.SubscriptionQueries
	actor    func(*fiber.Ctx) string
}

func NewSubscriptions(commands event.SubscriptionCommands, queries event.SubscriptionQueries, actor func(*fiber.Ctx) string) *Subscriptions {
	return &Subscriptions{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Subscriptions) WithActor(actor func(*fiber.Ctx) string) *Subscriptions {
	return &Subscriptions{commands: h.commands, queries: h.queries, actor: actor}
}

// Register mounts the routes under /webhooks of r.
func (h *Subscriptions) Register(r fiber.Router) { h.Routes(r.Group("/webhooks")) }

// Routes mounts the routes on a /webhooks group (the /api/v1 one carries
// its permission check).
func (h *Subscriptions) Routes(r fiber.Router) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/:subscription", h.Find)
	r.Patch("/:subscription", h.Update)
	r.Delete("/:subscription", h.Delete)
	r.Post("/:subscription/rotate-secret", h.Rotate)
	r.Post("/:subscription/test", h.Test)
	r.Post("/:subscription/replay", h.Replay)
	r.Get("/:subscription/deliveries", h.Deliveries)
	r.Post("/:subscription/deliveries/:delivery/retry", h.Retry)
}

func environment(c *fiber.Ctx) (identity.EnvironmentID, error) {
	id, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return id, errx.Validation("environment must be a valid UUID")
	}
	return id, nil
}

func subscription(c *fiber.Ctx) (identity.EnvironmentID, identity.SubscriptionID, error) {
	env, err := environment(c)
	if err != nil {
		return env, identity.SubscriptionID{}, err
	}
	id, err := identity.ParseSubscriptionID(c.Params("subscription"))
	if err != nil {
		return env, id, errx.NotFound("webhook subscription not found")
	}
	return env, id, nil
}

func (h *Subscriptions) mutation(c *fiber.Ctx, env identity.EnvironmentID, action string) event.Mutation {
	return event.Mutation{Environment: env, Actor: h.actor(c), Action: action}
}

func (h *Subscriptions) List(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListSubscriptions(c.UserContext(), env)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Subscriptions) Create(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	var input event.SubscriptionCreate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.CreateSubscription(c.UserContext(), h.mutation(c, env, event.ActionWebhookCreate), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Subscriptions) Find(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindSubscription(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Subscriptions) Update(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	var input event.SubscriptionUpdate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	if err := h.commands.UpdateSubscription(c.UserContext(), h.mutation(c, env, event.ActionWebhookUpdate), id, input); err != nil {
		return err
	}
	out, err := h.queries.FindSubscription(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Subscriptions) Delete(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	if err := h.commands.DeleteSubscription(c.UserContext(), h.mutation(c, env, event.ActionWebhookDelete), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Subscriptions) Rotate(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	out, err := h.commands.RotateSecret(c.UserContext(), h.mutation(c, env, event.ActionWebhookRotate), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Subscriptions) Test(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	out, err := h.commands.TestSubscription(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Subscriptions) Replay(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	var input event.Replay
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	n, err := h.commands.Replay(c.UserContext(), h.mutation(c, env, event.ActionWebhookReplay), id, input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"queued": n})
}

// Deliveries reads the delivery log. Query: status (pending, delivered,
// failed), limit, offset.
func (h *Subscriptions) Deliveries(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListDeliveries(c.UserContext(), env, id, event.DeliveryFilter{Status: c.Query("status")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Subscriptions) Retry(c *fiber.Ctx) error {
	env, id, err := subscription(c)
	if err != nil {
		return err
	}
	delivery, err := strconv.ParseInt(c.Params("delivery"), 10, 64)
	if err != nil || delivery <= 0 {
		return errx.NotFound("failed webhook delivery not found")
	}
	if err := h.commands.RetryDelivery(c.UserContext(), h.mutation(c, env, event.ActionWebhookRetry), id, delivery); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusAccepted)
}
