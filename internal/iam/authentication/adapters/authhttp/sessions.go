package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// selfToken authenticates the caller of a /me/sessions route: environment
// and audience come from the query.
func (h *Tokens) selfToken(c *fiber.Ctx, environment, audience string) (authentication.Token, error) {
	envID, _ := identity.ParseEnvironmentID(environment)
	return h.Validate(c, envID, audience)
}

// sessionSelf is the optional JSON body of revoke-others, an alternative
// to the query like the other /me POST routes.
type sessionSelf struct {
	Environment string `json:"environment_id"`
	Audience    string `json:"audience"`
}

// Sessions lists the caller's live sessions, newest first.
func (h *Tokens) Sessions(c *fiber.Ctx) error {
	token, err := h.selfToken(c, c.Query("environment_id"), c.Query("audience"))
	if err != nil {
		return err
	}
	out, err := h.queries.Sessions(c.UserContext(), token, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	c.Set("Cache-Control", "no-store")
	return c.JSON(out)
}

// RevokeSession ends one of the caller's sessions (the current one too).
func (h *Tokens) RevokeSession(c *fiber.Ctx) error {
	token, err := h.selfToken(c, c.Query("environment_id"), c.Query("audience"))
	if err != nil {
		return err
	}
	session, err := identity.ParseSessionID(c.Params("id"))
	if err != nil {
		return errx.NotFound("resource not found")
	}
	if err = h.commands.RevokeSession(c.UserContext(), token, session); err != nil {
		return err
	}
	return c.SendStatus(204)
}

// RevokeOtherSessions ends every session of the caller but the current one.
func (h *Tokens) RevokeOtherSessions(c *fiber.Ctx) error {
	input := sessionSelf{Environment: c.Query("environment_id"), Audience: c.Query("audience")}
	if len(c.Body()) > 0 {
		var body sessionSelf
		if err := c.BodyParser(&body); err != nil {
			return errx.Validation("invalid request")
		}
		if input.Environment == "" {
			input.Environment = body.Environment
		}
		if input.Audience == "" {
			input.Audience = body.Audience
		}
	}
	token, err := h.selfToken(c, input.Environment, input.Audience)
	if err != nil {
		return err
	}
	count, err := h.commands.RevokeOtherSessions(c.UserContext(), token)
	if err != nil {
		return err
	}
	return c.JSON(authentication.SessionsRevoked{Count: count})
}
