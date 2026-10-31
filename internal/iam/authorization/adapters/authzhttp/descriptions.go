package authzhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Descriptions serves the permission descriptions of a resource (D40):
// GET/PUT …/resources/:resource/permission-descriptions, in management and
// /api/v1 (the resources read/write permissions).
type Descriptions struct {
	commands authorization.DescriptionCommands
	queries  authorization.DescriptionQueries
	actor    func(*fiber.Ctx) string
}

func NewDescriptions(commands authorization.DescriptionCommands, queries authorization.DescriptionQueries, actor func(*fiber.Ctx) string) *Descriptions {
	return &Descriptions{commands, queries, actor}
}

// WithActor returns a copy naming the actor differently (/api/v1 names the
// token's subject).
func (h *Descriptions) WithActor(actor func(*fiber.Ctx) string) *Descriptions {
	out := *h
	out.actor = actor
	return &out
}

// Register mounts the routes on the environment group e.
func (h *Descriptions) Register(e fiber.Router) {
	e.Get("/resources/:resource/permission-descriptions", h.Get)
	e.Put("/resources/:resource/permission-descriptions", h.Put)
}

// DescriptionSet is the body of both routes.
type DescriptionSet struct {
	Items []authorization.PermissionDescription `json:"items"`
}

func resourceParam(c *fiber.Ctx) (identity.ResourceID, error) {
	id, err := identity.ParseResourceID(c.Params("resource"))
	if err != nil {
		return id, errx.NotFound("resource not found")
	}
	return id, nil
}

// Get returns the stored descriptions, every locale.
func (h *Descriptions) Get(c *fiber.Ctx) error {
	id, err := resourceParam(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Descriptions(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(DescriptionSet{Items: out})
}

// Put replaces the whole set; an empty items clears it.
func (h *Descriptions) Put(c *fiber.Ctx) error {
	id, err := resourceParam(c)
	if err != nil {
		return err
	}
	var in DescriptionSet
	if err := c.BodyParser(&in); err != nil {
		return errx.Validation("invalid request body")
	}
	m := authorization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
	if err := h.commands.SetDescriptions(c.UserContext(), m, id, in.Items); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
