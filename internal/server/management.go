package server

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/gofiber/fiber/v2"
)

func OperatorID(c *fiber.Ctx) string { return mgmthttp.Principal(c).OperatorID.String() }

// Owner reports whether the operator is a workspace owner.
func Owner(c *fiber.Ctx) bool { return mgmthttp.Principal(c).Role == "owner" }
func (s *Server) managementRoutes(r fiber.Router) {
	s.Control.Register(r)
	if s.OperatorSSO != nil {
		s.OperatorSSO.Register(r)
	}
	e := r.Group("/environments/:environment", s.Control.Environment)
	s.Users.Register(e)
	if s.AccessTokens != nil {
		s.AccessTokens.Register(e)
	}
	if s.UserKeys != nil {
		s.UserKeys.Register(e)
	}
	if s.Factors != nil {
		s.Factors.Register(e)
	}
	s.Organizations.Register(e)
	s.Authorization.Register(e)
	if s.ResourceGrants != nil {
		s.ResourceGrants.Register(e)
	}
	s.Applications.Register(e)
	s.ServiceAccounts.Register(e)
	s.administrationRoutes(e)
	s.Impersonation.Register(e)
	s.OAuth.RegisterManagement(e)
	if s.LogoutDeliveries != nil {
		s.LogoutDeliveries.Register(e)
	}
	s.Federation.Register(e)
	if s.Hosted != nil {
		s.Hosted.RegisterManagement(e)
	}
	s.ProvisioningControl.Register(e)
	if s.Delivery != nil {
		s.Delivery.Register(e)
	}
	if s.SMS != nil {
		s.SMS.Register(e)
	}
	if s.PasswordPolicy != nil {
		s.PasswordPolicy.Register(e)
	}
	if s.SignInPolicy != nil {
		s.SignInPolicy.Register(e)
	}
	if s.SigningKeys != nil {
		s.SigningKeys.Register(e)
	}
	if s.Features != nil {
		s.Features.Register(e)
	}
	if s.Actions != nil {
		s.Actions.Register(e)
	}
	if s.Limits != nil {
		s.Limits.Register(e)
	}
	if s.SAML != nil {
		s.SAML.Register(e)
	}
	if s.OrgAdminPortal != nil {
		s.OrgAdminPortal.Register(e)
	}
}
