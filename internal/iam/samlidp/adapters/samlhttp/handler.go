// Package samlhttp serves the SAML identity provider: the public metadata
// and single sign-on endpoints under /saml/:environment and service
// provider management under /management/v1/environments/:environment/saml.
package samlhttp

import (
	"net/url"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// bindingCookie binds the hosted sign-in to the browser; the hosted pages
// read the same cookie for OAuth and SAML tickets.
const bindingCookie = "__Host-iamkit-authorization"

// Form renders the page that posts fields to action in the environment's
// branding (hostedhttp.Handler.PostForm).
type Form func(c *fiber.Ctx, environment identity.EnvironmentID, action string, fields [][2]string) error

type Handler struct {
	commands samlidp.Commands
	queries  samlidp.Queries
	flows    samlidp.Flows
	actor    func(*fiber.Ctx) string
	form     Form
}

func New(commands samlidp.Commands, queries samlidp.Queries, flows samlidp.Flows, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, flows: flows, actor: actor}
}

// PostForm sets the page that submits responses to the ACS (set in
// bootstrap with hostedhttp.Handler.PostForm).
func (h *Handler) PostForm(form Form) { h.form = form }

func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Register mounts the management routes under an environment router.
func (h *Handler) Register(e fiber.Router) {
	e.Get("/saml/identity-provider", h.identityProvider)
	e.Get("/saml/service-providers", h.list)
	e.Post("/saml/service-providers", h.create)
	e.Get("/saml/service-providers/:id", h.find)
	e.Patch("/saml/service-providers/:id", h.update)
	e.Delete("/saml/service-providers/:id", h.delete)
}

func (h *Handler) mutation(c *fiber.Ctx) samlidp.Mutation {
	return samlidp.Mutation{Environment: env(c), Actor: h.actor(c)}
}

func id(c *fiber.Ctx) (identity.ServiceProviderID, error) {
	out, err := identity.ParseServiceProviderID(c.Params("id"))
	if err != nil {
		return identity.ServiceProviderID{}, errx.NotFound("service provider not found")
	}
	return out, nil
}

func (h *Handler) identityProvider(c *fiber.Ctx) error {
	out, err := h.queries.IdentityProvider(c.Context(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) list(c *fiber.Ctx) error {
	var filter samlidp.Filter
	if raw := c.Query("application_id"); raw != "" {
		application, err := identity.ParseApplicationID(raw)
		if err != nil {
			return err
		}
		filter.Application = application
	}
	out, err := h.queries.List(c.Context(), env(c), filter, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) find(c *fiber.Ctx) error {
	provider, err := id(c)
	if err != nil {
		return err
	}
	out, err := h.queries.Find(c.Context(), env(c), provider)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) create(c *fiber.Ctx) error {
	var input samlidp.Create
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Create(c.Context(), h.mutation(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) update(c *fiber.Ctx) error {
	provider, err := id(c)
	if err != nil {
		return err
	}
	var input samlidp.Update
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.Update(c.Context(), h.mutation(c), provider, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	provider, err := id(c)
	if err != nil {
		return err
	}
	if err := h.commands.Delete(c.Context(), h.mutation(c), provider); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Metadata serves the environment's IdP metadata.
func (h *Handler) Metadata(c *fiber.Ctx) error {
	environment := env(c)
	if environment.IsZero() {
		return errx.NotFound("environment not found")
	}
	out, err := h.flows.Metadata(c.Context(), environment)
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, "application/samlmetadata+xml")
	return c.Send(out)
}

// SSO receives an AuthnRequest (HTTP-Redirect or HTTP-POST binding), binds
// it to the browser and sends the browser to the hosted sign-in.
func (h *Handler) SSO(c *fiber.Ctx) error {
	environment := env(c)
	if environment.IsZero() {
		return errx.NotFound("environment not found")
	}
	message := samlidp.Message{Redirect: true, SAMLRequest: c.Query("SAMLRequest"), RelayState: c.Query("RelayState")}
	if c.Method() == fiber.MethodPost {
		message = samlidp.Message{SAMLRequest: c.FormValue("SAMLRequest"), RelayState: c.FormValue("RelayState")}
	}
	ticket, binding, err := h.flows.Begin(c.Context(), environment, message)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: bindingCookie, Value: binding, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.OAuthAuthorizationTicketTTL.Seconds())})
	c.Set("Cache-Control", "no-store")
	return c.Redirect("/hosted/login?"+url.Values{"ticket": {ticket}}.Encode(), fiber.StatusSeeOther)
}

// Target is the application a SAML ticket signs in to (the hosted pages'
// view of it).
func (h *Handler) Target(c *fiber.Ctx, ticket, binding string) (samlidp.Target, error) {
	return h.flows.Target(c.Context(), ticket, binding)
}

// Finish answers the parked AuthnRequest for the session the hosted pages
// issued: the browser posts the signed response to the ACS.
func (h *Handler) Finish(c *fiber.Ctx, ticket string, login samlidp.Login) error {
	response, err := h.flows.Finish(c.Context(), ticket, c.Cookies(bindingCookie), login)
	if err != nil {
		return err
	}
	c.Cookie(&fiber.Cookie{Name: bindingCookie, Value: "", Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: -1})
	fields := [][2]string{{"SAMLResponse", response.SAMLResponse}}
	if response.RelayState != "" {
		fields = append(fields, [2]string{"RelayState", response.RelayState})
	}
	if h.form == nil {
		return errx.Internal("SAML response page not configured")
	}
	return h.form(c, response.Environment, response.ACSURL, fields)
}
