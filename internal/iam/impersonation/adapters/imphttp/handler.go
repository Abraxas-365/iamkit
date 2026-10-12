package imphttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation"
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Issue answers the request with a signed token (authhttp.Tokens.Issue,
// injected by bootstrap; a function field so the OpenAPI generator binds it,
// see openapigen.Bindings).
type Issue func(c *fiber.Ctx, t authentication.Token, audience, refresh string) error

// Operator is the management operator behind the request
// (mgmthttp.Principal, injected by bootstrap).
type Operator func(c *fiber.Ctx) management.Principal

type Handler struct {
	commands impersonation.Commands
	issue    Issue
	operator Operator
}

func New(commands impersonation.Commands, issue Issue, operator Operator) *Handler {
	return &Handler{commands, issue, operator}
}
func (h *Handler) Register(r fiber.Router) { r.Post("/impersonations", h.create) }
func (h *Handler) create(c *fiber.Ctx) error {
	var input impersonation.Request
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	envID, _ := identity.ParseEnvironmentID(c.Params("environment"))
	token, audience, err := h.commands.Create(c.UserContext(), h.operator(c), envID, input)
	if err != nil {
		return err
	}
	return h.issue(c, token, audience, "")
}
