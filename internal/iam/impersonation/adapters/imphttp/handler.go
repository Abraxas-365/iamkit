package imphttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands impersonation.Commands
	tokens   *authhttp.Tokens
}

func New(commands impersonation.Commands, tokens *authhttp.Tokens) *Handler {
	return &Handler{commands, tokens}
}
func (h *Handler) Register(r fiber.Router) { r.Post("/impersonations", h.create) }
func (h *Handler) create(c *fiber.Ctx) error {
	var input impersonation.Request
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	envID, _ := identity.ParseEnvironmentID(c.Params("environment"))
	token, audience, err := h.commands.Create(c.Context(), mgmthttp.Principal(c), envID, input)
	if err != nil {
		return err
	}
	return h.tokens.Issue(c, token, audience, "")
}
