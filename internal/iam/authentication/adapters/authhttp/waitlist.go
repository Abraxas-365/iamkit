package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// WaitlistHandler serves the sign-up waitlist
// (…/environments/:environment/waitlist).
type WaitlistHandler struct {
	commands authentication.WaitlistCommands
	queries  authentication.WaitlistQueries
	actor    func(*fiber.Ctx) string
}

func NewWaitlistHandler(commands authentication.WaitlistCommands, queries authentication.WaitlistQueries, actor func(*fiber.Ctx) string) *WaitlistHandler {
	return &WaitlistHandler{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *WaitlistHandler) WithActor(actor func(*fiber.Ctx) string) *WaitlistHandler {
	return &WaitlistHandler{commands: h.commands, queries: h.queries, actor: actor}
}

// Register mounts the routes under /waitlist of r.
func (h *WaitlistHandler) Register(r fiber.Router) { h.Routes(r.Group("/waitlist")) }

// Routes mounts the routes on a /waitlist group (the /api/v1 one carries its
// permission check). The bulk route comes before /:id.
func (h *WaitlistHandler) Routes(r fiber.Router) {
	r.Get("/", h.List)
	r.Post("/approve", h.ApproveMany)
	r.Get("/:id", h.Find)
	r.Post("/:id/approve", h.Approve)
	r.Post("/:id/reject", h.Reject)
	r.Delete("/:id", h.Delete)
}

func (h *WaitlistHandler) entry(c *fiber.Ctx) (identity.WaitlistEntryID, error) {
	id, err := identity.ParseWaitlistEntryID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("waitlist entry not found")
	}
	return id, nil
}

func (h *WaitlistHandler) mutation(c *fiber.Ctx) authentication.Mutation {
	return authentication.Mutation{Environment: envParam(c), Actor: h.actor(c)}
}

// List returns the entries (?status=, ?email= prefix, ?limit=, ?offset=),
// newest first.
func (h *WaitlistHandler) List(c *fiber.Ctx) error {
	out, err := h.queries.List(c.UserContext(), envParam(c), authentication.WaitlistFilter{Status: c.Query("status"), Email: c.Query("email")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *WaitlistHandler) Find(c *fiber.Ctx) error {
	id, err := h.entry(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Find(c.UserContext(), envParam(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Approve emails the person their sign-up link.
func (h *WaitlistHandler) Approve(c *fiber.Ctx) error {
	id, err := h.entry(c)
	if err != nil {
		return err
	}
	out, err := h.commands.Approve(c.UserContext(), h.mutation(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// ApproveMany approves the listed ids or every pending entry (oldest first),
// at most config.WaitlistMaxApprove per call.
func (h *WaitlistHandler) ApproveMany(c *fiber.Ctx) error {
	var input authentication.WaitlistApprove
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.ApproveMany(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Reject refuses the entry; silent unless {"notify": true}. The body is
// optional.
func (h *WaitlistHandler) Reject(c *fiber.Ctx) error {
	id, err := h.entry(c)
	if err != nil {
		return err
	}
	var input authentication.WaitlistRejection
	if len(c.Body()) > 0 {
		if err = c.BodyParser(&input); err != nil {
			return errx.Validation("invalid request")
		}
	}
	out, err := h.commands.Reject(c.UserContext(), h.mutation(c), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Delete removes the entry, freeing its email.
func (h *WaitlistHandler) Delete(c *fiber.Ctx) error {
	id, err := h.entry(c)
	if err != nil {
		return err
	}
	if err = h.commands.Delete(c.UserContext(), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
