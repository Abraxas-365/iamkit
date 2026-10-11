package server

import (
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// clientInfo puts the request's client (c.IP(), which honours
// Server.TrustedProxies, and the User-Agent) in the request context, where
// the writers of sessions read it (identity.ClientInfoFrom) to record where
// a session was opened from. It runs for every route: sign-ins arrive over
// /identity/v1, /oauth, /hosted, the federation and SAML callbacks, and
// operator impersonation over management and /api/v1.
func clientInfo(c *fiber.Ctx) error {
	c.SetUserContext(identity.WithClientInfo(c.UserContext(), identity.NewClientInfo(c.IP(), c.Get(fiber.HeaderUserAgent))))
	return c.Next()
}
