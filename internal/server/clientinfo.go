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
// operator impersonation over management and /api/v1. The GeoIPHeader
// country is believed only from a trusted proxy (never without
// TrustedProxies).
func (s *Server) clientInfo(c *fiber.Ctx) error {
	info := identity.NewClientInfo(c.IP(), c.Get(fiber.HeaderUserAgent))
	if s.GeoIPHeader != "" && len(s.TrustedProxies) > 0 && c.IsProxyTrusted() {
		info = info.WithCountry(c.Get(s.GeoIPHeader))
	}
	c.SetUserContext(identity.WithClientInfo(c.UserContext(), info))
	return c.Next()
}
