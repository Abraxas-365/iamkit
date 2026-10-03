package authhttp

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Tokens struct {
	issuer    authentication.TokenIssuer
	validator authentication.TokenValidator
	commands  authentication.SessionCommands
	queries   authentication.SessionQueries
}

func NewTokens(issuer authentication.TokenIssuer, validator authentication.TokenValidator, commands authentication.SessionCommands, queries authentication.SessionQueries) *Tokens {
	return &Tokens{issuer: issuer, validator: validator, commands: commands, queries: queries}
}
func bearer(c *fiber.Ctx) string {
	parts := strings.Fields(c.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
func (h *Tokens) Validate(c *fiber.Ctx, environment identity.EnvironmentID, audience string) (authentication.Token, error) {
	return h.validator.Validate(c.UserContext(), bearer(c), audience, environment)
}

// Self validates the bearer token by its own claims (any environment and
// audience IAMKit issued it for) and reads the user's profile.
func (h *Tokens) Self(c *fiber.Ctx) (authentication.Token, authentication.Profile, error) {
	token, err := h.validator.ValidateSelf(c.UserContext(), bearer(c))
	if err != nil {
		return token, authentication.Profile{}, err
	}
	profile, err := h.queries.Profile(c.UserContext(), token)
	return token, profile, err
}

// ProfileOf reads the profile of a token resolved elsewhere (an opaque
// OAuth access token introspected by the OAuth module).
func (h *Tokens) ProfileOf(c *fiber.Ctx, token authentication.Token) (authentication.Profile, error) {
	return h.queries.Profile(c.UserContext(), token)
}

// Verify validates a raw access token by its own claims, like Self does
// for the bearer token (OAuth token exchange subject tokens).
func (h *Tokens) Verify(c *fiber.Ctx, raw string) (authentication.Token, error) {
	return h.validator.ValidateSelf(c.UserContext(), raw)
}

// Sign issues an access token for audience without writing a response.
func (h *Tokens) Sign(c *fiber.Ctx, t authentication.Token, audience string) (string, error) {
	return h.issuer.Issue(c.UserContext(), t, audience)
}
func (h *Tokens) Issue(c *fiber.Ctx, t authentication.Token, audience, refresh string) error {
	return h.IssueWith(c, t, audience, refresh, nil)
}

// IssueWith answers a login that enrolled its first second factor with
// the recovery codes, shown this once.
func (h *Tokens) IssueWith(c *fiber.Ctx, t authentication.Token, audience, refresh string, recoveryCodes []string) error {
	raw, err := h.issuer.Issue(c.UserContext(), t, audience)
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	out := tokenBody(raw, refresh)
	if len(recoveryCodes) > 0 {
		out["recovery_codes"] = recoveryCodes
	}
	return c.JSON(out)
}
func tokenBody(raw, refresh string) fiber.Map {
	out := fiber.Map{"access_token": raw, "token_type": "Bearer", "expires_in": int(config.TokenTTL.Seconds())}
	if refresh != "" {
		out["refresh_token"] = refresh
	}
	return out
}
func tokenResponse(c *fiber.Ctx, raw, refresh string) error {
	c.Set("Cache-Control", "no-store")
	return c.JSON(tokenBody(raw, refresh))
}
func (h *Tokens) Machine(c *fiber.Ctx) error {
	raw, err := h.issuer.Machine(c.UserContext(), bearer(c))
	if err != nil {
		return err
	}
	return tokenResponse(c, raw, "")
}

// ExchangeAccessToken trades the personal access token in the
// Authorization header for an application access token.
func (h *Tokens) ExchangeAccessToken(c *fiber.Ctx) error {
	raw, err := h.issuer.ExchangeAccessToken(c.UserContext(), bearer(c))
	if err != nil {
		return err
	}
	return tokenResponse(c, raw, "")
}

// IssueMachine is the token response of an already authenticated service
// account (OAuth client_credentials); it sets Cache-Control like Machine.
func (h *Tokens) IssueMachine(c *fiber.Ctx, account identity.AccountID) (fiber.Map, error) {
	raw, err := h.issuer.MachineAccount(c.UserContext(), account)
	if err != nil {
		return nil, err
	}
	c.Set("Cache-Control", "no-store")
	return tokenBody(raw, ""), nil
}

// KeyGrant is the token response of a machine user's JWT-bearer
// assertion (OAuth urn:ietf:params:oauth:grant-type:jwt-bearer).
func (h *Tokens) KeyGrant(c *fiber.Ctx, assertion string, boundary authentication.Context) (fiber.Map, error) {
	raw, err := h.issuer.KeyGrant(c.UserContext(), assertion, boundary)
	if err != nil {
		return nil, err
	}
	c.Set("Cache-Control", "no-store")
	return tokenBody(raw, ""), nil
}
func (h *Tokens) JWKS(c *fiber.Ctx) error {
	out, err := h.issuer.JWKS(c.UserContext())
	if err != nil {
		return err
	}
	// Caches may keep it briefly: a new key is published before it signs.
	c.Set("Cache-Control", "public, max-age=60")
	return c.JSON(out)
}
func (h *Tokens) Introspect(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Audience    string                 `json:"audience"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	c.Set("Cache-Control", "no-store")
	// An outage is not an inactive token: a resource server must not end a
	// user's session because IAMKit could not reach its database.
	if errx.IsServerError(err) {
		return err
	}
	if err != nil {
		return c.JSON(fiber.Map{"active": false})
	}
	return c.JSON(fiber.Map{"active": true, "claims": token})
}
func (h *Tokens) Logout(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Audience    string                 `json:"audience"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	if err = h.commands.Logout(c.UserContext(), token); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Tokens) Profile(c *fiber.Ctx) error {
	envID, _ := identity.ParseEnvironmentID(c.Query("environment_id"))
	token, err := h.Validate(c, envID, c.Query("audience"))
	if err != nil {
		return err
	}
	out, err := h.queries.Profile(c.UserContext(), token)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Tokens) Organizations(c *fiber.Ctx) error {
	envID, _ := identity.ParseEnvironmentID(c.Query("environment_id"))
	token, err := h.Validate(c, envID, c.Query("audience"))
	if err != nil {
		return err
	}
	out, err := h.queries.Organizations(c.UserContext(), token)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
func (h *Tokens) UpdateProfile(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Audience    string                 `json:"audience"`
		authentication.ProfileUpdate
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	if err = h.commands.UpdateProfile(c.UserContext(), token, input.ProfileUpdate); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *Tokens) AddMember(c *fiber.Ctx) error {
	var input struct {
		Environment identity.EnvironmentID `json:"environment_id"`
		Audience    string                 `json:"audience"`
		User        string                 `json:"user_id"`
	}
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	token, err := h.Validate(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	var user identity.UserID
	if input.User != "" {
		if user, err = identity.ParseUserID(input.User); err != nil {
			return errx.Validation("user_id must be a valid user ID")
		}
	}
	if err = h.commands.AddMember(c.UserContext(), token, user); err != nil {
		return err
	}
	return c.SendStatus(201)
}
