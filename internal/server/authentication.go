package server

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

func (s *Server) IssueSession(c *fiber.Ctx, out authentication.Issued) error {
	var authTime int64
	if !out.Authenticated.IsZero() {
		authTime = out.Authenticated.Unix()
	}
	return s.Tokens.IssueWith(c, authentication.Token{Access: identity.Access{EnvironmentID: out.Context.EnvironmentID, OrganizationID: out.Context.OrganizationID, ApplicationID: out.Context.ApplicationID, ResourceID: out.Context.ResourceID, Permissions: out.Access.Permissions}, Subject: out.User, SessionID: out.Session, Purpose: "application", AMR: out.AMR, AuthTime: authTime}, out.Access.Audience, out.Refresh, out.RecoveryCodes)
}

// RespondLogin answers a headless login step: tokens, or mfa_required.
func (s *Server) RespondLogin(c *fiber.Ctx, out authentication.Result) error {
	return authhttp.Respond(c, out, s.IssueSession)
}
