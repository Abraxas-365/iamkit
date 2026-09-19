package userhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands user.Commands
	queries  user.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands user.Commands, queries user.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}
func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *Handler) Register(r fiber.Router) {
	r.Post("/users", h.Create)
	r.Get("/users", h.List)
	r.Get("/users/:id", h.Find)
	r.Patch("/users/:id", h.Update)
	r.Delete("/users/:id", h.Suspend)
}
func (h *Handler) Create(c *fiber.Ctx) error {
	var input user.Create
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	id, err := h.commands.Create(c.Context(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) List(c *fiber.Ctx) error {
	users, err := h.queries.List(c.Context(), env(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	type summary struct {
		ID     identity.UserID `json:"id"`
		Email  string          `json:"email"`
		Name   string          `json:"name"`
		Active bool            `json:"active"`
	}
	out := make([]summary, 0, len(users.Items))
	for _, u := range users.Items {
		out = append(out, summary{u.ID, u.Email, u.Name, u.Active})
	}
	return c.JSON(query.Paginated[summary]{Items: out, Page: users.Page})
}
func (h *Handler) Find(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	u, err := h.queries.Find(c.Context(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(u)
}
func (h *Handler) Update(c *fiber.Ctx) error {
	var input user.Update
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.Validation("invalid user id")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Update(c.Context(), m, id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Suspend(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err := h.commands.Suspend(c.Context(), env(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
