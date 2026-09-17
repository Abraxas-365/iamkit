package server

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

func (s *Server) IssueSession(c *fiber.Ctx, out authentication.Issued) error {
	return s.Tokens.Issue(c, authentication.Token{Access: identity.Access{EnvironmentID: out.Context.EnvironmentID, OrganizationID: out.Context.OrganizationID, ApplicationID: out.Context.ApplicationID, ResourceID: out.Context.ResourceID, Permissions: out.Access.Permissions}, Subject: out.User, SessionID: out.Session, Purpose: "application"}, out.Access.Audience, out.Refresh)
}
