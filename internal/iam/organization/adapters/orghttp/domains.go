package orghttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Domains serves /organizations/:organization/domains. Routes are registered
// on a router that already verified the organization (Structure.Check).
type Domains struct {
	commands organization.DomainCommands
	queries  organization.DomainQueries
	actor    func(*fiber.Ctx) string
}

func NewDomains(commands organization.DomainCommands, queries organization.DomainQueries, actor func(*fiber.Ctx) string) *Domains {
	return &Domains{commands, queries, actor}
}

func (h *Domains) RegisterViews(r fiber.Router) {
	r.Get("/domains", h.List)
	r.Get("/domains/:domain", h.Find)
}

func (h *Domains) RegisterMutations(r fiber.Router) {
	r.Post("/domains", h.Create)
	r.Post("/domains/:domain/verify", h.Verify)
	r.Post("/domains/:domain/force-verify", h.ForceVerify)
	r.Delete("/domains/:domain", h.Delete)
}

func (h *Domains) mutation(c *fiber.Ctx) organization.Mutation {
	return organization.Mutation{Environment: env(c), Actor: h.actor(c), Action: c.Method(), Target: c.Path()}
}

func domainID(c *fiber.Ctx) (identity.DomainID, error) {
	id, err := identity.ParseDomainID(c.Params("domain"))
	if err != nil {
		return id, errx.NotFound("domain not found")
	}
	return id, nil
}

func (h *Domains) List(c *fiber.Ctx) error {
	out, err := h.queries.ListDomains(c.Context(), boundary(c), httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Domains) Find(c *fiber.Ctx) error {
	id, err := domainID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindDomain(c.Context(), boundary(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Domains) Create(c *fiber.Ctx) error {
	var input organization.DomainInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.AddDomain(c.Context(), boundary(c), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.Status(201).JSON(out)
}

func (h *Domains) Verify(c *fiber.Ctx) error {
	id, err := domainID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.VerifyDomain(c.Context(), boundary(c), h.mutation(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Domains) ForceVerify(c *fiber.Ctx) error {
	id, err := domainID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.ForceVerifyDomain(c.Context(), boundary(c), h.mutation(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Domains) Delete(c *fiber.Ctx) error {
	id, err := domainID(c)
	if err != nil {
		return err
	}
	if err := h.commands.DeleteDomain(c.Context(), boundary(c), h.mutation(c), id); err != nil {
		return err
	}
	return c.SendStatus(204)
}
