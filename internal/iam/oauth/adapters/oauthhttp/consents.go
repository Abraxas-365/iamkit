package oauthhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// SelfValidate checks the caller's access token for an environment and
// audience (empty: any the token was issued for).
type SelfValidate func(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error)

// Consents serves what people and operators do with consents and
// administrator grants (D31-D33):
//   - self-service /identity/v1/me/connected-apps[/:client] (application
//     tokens of people; impersonated tokens read only);
//   - operator …/users/:id/connected-apps[/:client] (/api/v1:
//     iam:users:read/write);
//   - operator …/protected-resources/:id/clients/:client/grants[/:grant]
//     (/api/v1: iam:protected-resources:read/write).
type Consents struct {
	commands oauth.ConsentCommands
	queries  oauth.ConsentQueries
	actor    func(*fiber.Ctx) string
	validate SelfValidate
}

func NewConsents(commands oauth.ConsentCommands, queries oauth.ConsentQueries, actor func(*fiber.Ctx) string) *Consents {
	return &Consents{commands: commands, queries: queries, actor: actor}
}

// WithActor returns a copy naming the actor differently (the /api/v1
// routes name the token's subject).
func (h *Consents) WithActor(actor func(*fiber.Ctx) string) *Consents {
	out := *h
	out.actor = actor
	return &out
}

// SetValidate wires the self-service token check (the authentication
// module's, set in bootstrap).
func (h *Consents) SetValidate(validate SelfValidate) { h.validate = validate }

// Register mounts the operator routes on the environment group r.
func (h *Consents) Register(r fiber.Router) {
	h.UserRoutes(r.Group("/users"))
	h.GrantRoutes(r.Group("/protected-resources"))
}

// UserRoutes mounts a user's connected apps on a /users group.
func (h *Consents) UserRoutes(r fiber.Router) {
	r.Get("/:id/connected-apps", h.userApps)
	r.Delete("/:id/connected-apps/:client", h.disconnectUser)
}

// GrantRoutes mounts the administrator grants on a /protected-resources
// group.
func (h *Consents) GrantRoutes(r fiber.Router) {
	r.Get("/:id/clients/:client/grants", h.grants)
	r.Put("/:id/clients/:client/grants", h.grant)
	r.Delete("/:id/clients/:client/grants/:grant", h.revokeGrant)
}

// SelfRoutes mounts the self-service routes on /identity/v1 behind limit.
func (h *Consents) SelfRoutes(r fiber.Router, limit fiber.Handler) {
	r.Get("/me/connected-apps", limit, h.myApps)
	r.Delete("/me/connected-apps/:client", limit, h.disconnectMe)
}

func organizationFilter(c *fiber.Ctx) (*identity.OrganizationID, error) {
	raw := c.Query("organization_id")
	if raw == "" {
		return nil, nil
	}
	id, err := identity.ParseOrganizationID(raw)
	if err != nil {
		return nil, errx.Validation("organization_id is not a valid id")
	}
	return &id, nil
}

func userParam(c *fiber.Ctx) (identity.UserID, error) {
	id, err := identity.ParseUserID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("user not found")
	}
	return id, nil
}

func (h *Consents) userApps(c *fiber.Ctx) error {
	user, err := userParam(c)
	if err != nil {
		return err
	}
	org, err := organizationFilter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ConnectedApps(c.UserContext(), env(c), user, oauth.ConnectedAppFilter{Organization: org, Locales: readerLocales(c)})
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Consents) disconnectUser(c *fiber.Ctx) error {
	user, err := userParam(c)
	if err != nil {
		return err
	}
	client, err := clientParam(c)
	if err != nil {
		return err
	}
	org, err := organizationFilter(c)
	if err != nil {
		return err
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: oauth.ActionConsentRevoke, Target: client.String()}
	if err = h.commands.Disconnect(c.UserContext(), m, oauth.Disconnect{User: user, Client: client, Organization: org, Reason: oauth.ConsentRevokedByOperator}); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// self authenticates the bearer: an application token of a person.
func (h *Consents) self(c *fiber.Ctx, write bool) (authentication.Token, error) {
	if h.validate == nil {
		return authentication.Token{}, errx.Unauthorized("invalid token")
	}
	environment, _ := identity.ParseEnvironmentID(c.Query("environment_id"))
	token, err := h.validate(c, environment, c.Query("audience"))
	if err != nil {
		return token, err
	}
	if token.Purpose != authentication.PurposeApplication || token.Subject.IsZero() {
		return token, errx.Forbidden("a user access token is required")
	}
	if write && token.Impersonated() {
		return token, errx.Forbidden("impersonated sessions cannot disconnect apps")
	}
	return token, nil
}

func (h *Consents) myApps(c *fiber.Ctx) error {
	t, err := h.self(c, false)
	if err != nil {
		return err
	}
	org, err := organizationFilter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ConnectedApps(c.UserContext(), t.EnvironmentID, t.Subject, oauth.ConnectedAppFilter{Organization: org, Locales: readerLocales(c)})
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(fiber.Map{"items": out})
}

func (h *Consents) disconnectMe(c *fiber.Ctx) error {
	t, err := h.self(c, true)
	if err != nil {
		return err
	}
	client, err := clientParam(c)
	if err != nil {
		return err
	}
	org, err := organizationFilter(c)
	if err != nil {
		return err
	}
	// The user acts on their own account: no operator audit row, the
	// oauth_consent.revoked events name them as the actor.
	m := oauth.Mutation{Environment: t.EnvironmentID, Actor: t.Subject.String()}
	if err = h.commands.Disconnect(c.UserContext(), m, oauth.Disconnect{User: t.Subject, Client: client, Organization: org, Reason: oauth.ConsentRevokedByUser}); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func grantParams(c *fiber.Ctx) (identity.ProtectedResourceID, identity.ClientID, error) {
	protected, err := protectedID(c)
	if err != nil {
		return protected, identity.ClientID{}, err
	}
	client, err := clientParam(c)
	return protected, client, err
}

func (h *Consents) grants(c *fiber.Ctx) error {
	protected, client, err := grantParams(c)
	if err != nil {
		return err
	}
	out, err := h.queries.ListClientGrants(c.UserContext(), env(c), protected, oauth.ClientGrantFilter{Client: &client, Revoked: c.QueryBool("revoked")})
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Consents) grant(c *fiber.Ctx) error {
	protected, client, err := grantParams(c)
	if err != nil {
		return err
	}
	var input oauth.ClientGrantInput
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: oauth.ActionClientGrant, Target: client.String()}
	out, err := h.commands.GrantClient(c.UserContext(), m, protected, client, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Consents) revokeGrant(c *fiber.Ctx) error {
	protected, client, err := grantParams(c)
	if err != nil {
		return err
	}
	grant, err := identity.ParseClientGrantID(c.Params("grant"))
	if err != nil {
		return errx.NotFound("grant not found")
	}
	m := oauth.Mutation{Environment: env(c), Actor: h.actor(c), Action: oauth.ActionClientGrantRevoke, Target: client.String()}
	if err = h.commands.RevokeClientGrant(c.UserContext(), m, protected, client, grant); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// readerLocales are the languages the caller prefers, best first: the
// `locale` query parameter, then Accept-Language (D40; permission
// descriptions are worded in the first the catalog has).
func readerLocales(c *fiber.Ctx) []string {
	return []string{c.Query("locale"), c.Get(fiber.HeaderAcceptLanguage)}
}
