package userhttp

import (
	"time"

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
	validate Validate // nil: no self-service routes
	phones   user.PhoneCommands
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
	r.Delete("/users/:id/permanent", h.Delete)
	r.Post("/users/:id/unlock", h.Unlock)
	r.Post("/users/:id/deactivate", h.Suspend)
	r.Post("/users/:id/reactivate", h.Reactivate)
	r.Get("/users/:id/metadata/:key", h.Metadata)
	r.Put("/users/:id/metadata/:key", h.SetMetadata)
	r.Delete("/users/:id/metadata/:key", h.DeleteMetadata)
	r.Patch("/users/:id/profile", h.UpdateProfile)
	h.RegisterSchema(r)
}

// RegisterSchema mounts the environment's user schema routes.
func (h *Handler) RegisterSchema(r fiber.Router) {
	r.Get("/user-schema", h.Schema)
	r.Put("/user-schema", h.SaveSchema)
	r.Delete("/user-schema", h.DeleteSchema)
}
func (h *Handler) Create(c *fiber.Ctx) error {
	var input user.Create
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	id, err := h.commands.Create(c.UserContext(), env(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(fiber.Map{"id": id})
}
func (h *Handler) List(c *fiber.Ctx) error {
	filter := user.Filter{State: user.State(c.Query("state")), Kind: user.Kind(c.Query("kind"))}
	if raw := c.Query("home_organization_id"); raw != "" {
		org, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return errx.Validation("home_organization_id must be a valid UUID")
		}
		filter.HomeOrganization = org
	}
	users, err := h.queries.List(c.UserContext(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	type summary struct {
		ID               identity.UserID          `json:"id"`
		Kind             user.Kind                `json:"kind"`
		Email            string                   `json:"email"`
		Name             string                   `json:"name"`
		Username         string                   `json:"username"`
		HomeOrganization *identity.OrganizationID `json:"home_organization_id"`
		AvatarURL        string                   `json:"avatar_url"`
		Active           bool                     `json:"active"`
		State            user.State               `json:"state"`
		LastSignedInAt   *time.Time               `json:"last_signed_in_at"`
	}
	out := make([]summary, 0, len(users.Items))
	for _, u := range users.Items {
		out = append(out, summary{u.ID, u.Kind, u.Email, u.Name, u.Username, u.HomeOrganization, u.AvatarURL, u.Active, u.State, u.LastSignedInAt})
	}
	return c.JSON(query.Paginated[summary]{Items: out, Page: users.Page})
}
func (h *Handler) Find(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	u, err := h.queries.Find(c.UserContext(), env(c), id)
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
	if err := h.commands.Update(c.UserContext(), m, id, input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Suspend(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: id.String()}
	if err := h.commands.Deactivate(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// Reactivate lifts a suspension.
func (h *Handler) Reactivate(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: id.String()}
	if err := h.commands.Reactivate(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.Delete(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Handler) Unlock(c *fiber.Ctx) error {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	m := user.Mutation{Environment: env(c), Actor: h.actor(c), Target: c.Path()}
	if err := h.commands.Unlock(c.UserContext(), m, id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
