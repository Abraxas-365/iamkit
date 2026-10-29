package oauthhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Admissions serves what IT does with the clients of metadata documents:
// …/protected-resources/:id/clients[/:client[/approve|block|unblock|requests]],
// …/protected-resources/:id/client-templates, …/oauth-client-allowlist and
// …/oauth-client-presets. /api/v1 guards them with
// iam:protected-resources:read/write like the resources themselves.
type Admissions struct {
	commands oauth.AdmissionCommands
	queries  oauth.AdmissionQueries
	actor    func(*fiber.Ctx) string
}

func NewAdmissions(commands oauth.AdmissionCommands, queries oauth.AdmissionQueries, actor func(*fiber.Ctx) string) *Admissions {
	return &Admissions{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Admissions) WithActor(actor func(*fiber.Ctx) string) *Admissions {
	return &Admissions{commands: h.commands, queries: h.queries, actor: actor}
}

// ResourceRoutes mounts the per-server routes on a /protected-resources
// group.
func (h *Admissions) ResourceRoutes(r fiber.Router) {
	r.Get("/:id/clients", h.listClients)
	r.Get("/:id/clients/:client", h.findClient)
	r.Get("/:id/clients/:client/requests", h.requests)
	r.Get("/:id/clients/:client/impact", h.impact)
	r.Post("/:id/clients/:client/approve", h.approve)
	r.Post("/:id/clients/:client/block", h.block)
	r.Post("/:id/clients/:client/unblock", h.unblock)
	r.Delete("/:id/clients/:client", h.forget)
	r.Post("/:id/client-templates", h.template)
}

// AllowlistRoutes mounts the allowlist on an /oauth-client-allowlist group.
func (h *Admissions) AllowlistRoutes(r fiber.Router) {
	r.Get("/", h.listAllowlist)
	r.Post("/", h.createAllowlist)
	r.Delete("/:entry", h.deleteAllowlist)
}

// PresetRoutes mounts the catalog on an /oauth-client-presets group.
func (h *Admissions) PresetRoutes(r fiber.Router) {
	r.Get("/", h.presets)
	r.Post("/", h.applyPreset)
}

// Register mounts every route on the environment group r.
func (h *Admissions) Register(r fiber.Router) {
	h.ResourceRoutes(r.Group("/protected-resources"))
	h.AllowlistRoutes(r.Group("/oauth-client-allowlist"))
	h.PresetRoutes(r.Group("/oauth-client-presets"))
}

func (h *Admissions) mutation(c *fiber.Ctx) oauth.Mutation {
	return oauth.Mutation{Environment: env(c), Actor: h.actor(c)}
}

func clientParam(c *fiber.Ctx) (identity.ClientID, error) {
	id, err := identity.ParseClientID(c.Params("client"))
	if err != nil {
		return id, errx.NotFound("client not found")
	}
	return id, nil
}

func (h *Admissions) listClients(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListExternalClients(c.UserContext(), env(c), id, oauth.ExternalClientFilter{Admission: c.Query("admission")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Admissions) findClient(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	client, err := clientParam(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindExternalClient(c.UserContext(), env(c), id, client)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// impact returns the live sessions, and their people, that blocking or
// forgetting the client would end.
func (h *Admissions) impact(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	client, err := clientParam(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ExternalClientImpact(c.UserContext(), env(c), id, client)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Admissions) requests(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	client, err := clientParam(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListAccessRequests(c.UserContext(), env(c), id, client, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// decide runs one decision on a client and answers with the client as it
// stands (nil view after a delete).
func (h *Admissions) decide(c *fiber.Ctx, run func(m oauth.Mutation, id identity.ProtectedResourceID, client identity.ClientID) error, show bool) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	client, err := clientParam(c)
	if err != nil {
		return err
	}
	if err = run(h.mutation(c), id, client); err != nil {
		return err
	}
	if !show {
		return c.SendStatus(fiber.StatusNoContent)
	}
	out, err := h.queries.FindExternalClient(c.UserContext(), env(c), id, client)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Admissions) approve(c *fiber.Ctx) error {
	var input oauth.Approval
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&input); err != nil {
			return errx.Validation("invalid request")
		}
	}
	return h.decide(c, func(m oauth.Mutation, id identity.ProtectedResourceID, client identity.ClientID) error {
		return h.commands.ApproveClient(c.UserContext(), m, id, client, input)
	}, true)
}

func (h *Admissions) block(c *fiber.Ctx) error {
	return h.decide(c, func(m oauth.Mutation, id identity.ProtectedResourceID, client identity.ClientID) error {
		return h.commands.BlockClient(c.UserContext(), m, id, client)
	}, true)
}

func (h *Admissions) unblock(c *fiber.Ctx) error {
	return h.decide(c, func(m oauth.Mutation, id identity.ProtectedResourceID, client identity.ClientID) error {
		return h.commands.UnblockClient(c.UserContext(), m, id, client)
	}, true)
}

func (h *Admissions) forget(c *fiber.Ctx) error {
	return h.decide(c, func(m oauth.Mutation, id identity.ProtectedResourceID, client identity.ClientID) error {
		return h.commands.ForgetClient(c.UserContext(), m, id, client)
	}, false)
}

func (h *Admissions) template(c *fiber.Ctx) error {
	id, err := protectedID(c)
	if err != nil {
		return err
	}
	var input oauth.PresetApply
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.CreateClientTemplate(c.UserContext(), h.mutation(c), id, input)
	if err != nil {
		return err
	}
	status := fiber.StatusOK
	if out.Client != nil && out.Client.Created {
		status = fiber.StatusCreated
	}
	return c.Status(status).JSON(out)
}

func (h *Admissions) listAllowlist(c *fiber.Ctx) error {
	var protected *identity.ProtectedResourceID
	if raw := c.Query("protected_resource_id"); raw != "" {
		id, err := identity.ParseProtectedResourceID(raw)
		if err != nil {
			return errx.Validation("protected_resource_id must be a valid UUID")
		}
		protected = &id
	}
	out, err := h.queries.ListAllowlist(c.UserContext(), env(c), protected, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Admissions) createAllowlist(c *fiber.Ctx) error {
	var input oauth.AllowlistCreate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.CreateAllowlistEntry(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Admissions) deleteAllowlist(c *fiber.Ctx) error {
	entry, err := identity.ParseAllowlistEntryID(c.Params("entry"))
	if err != nil {
		return errx.NotFound("allowlist entry not found")
	}
	if err = h.commands.DeleteAllowlistEntry(c.UserContext(), h.mutation(c), entry); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Admissions) presets(c *fiber.Ctx) error {
	out, err := h.queries.ListPresets(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Admissions) applyPreset(c *fiber.Ctx) error {
	var input oauth.PresetApply
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.ApplyPreset(c.UserContext(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}
