package server

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/gofiber/fiber/v2"
)

func OperatorID(c *fiber.Ctx) string { return mgmthttp.Principal(c).OperatorID.String() }
func (s *Server) managementRoutes(r fiber.Router) {
	s.Control.Register(r)
	e := r.Group("/environments/:environment", s.Control.Environment)
	s.Users.Register(e)
	s.Organizations.Register(e)
	s.Authorization.Register(e)
	s.Applications.Register(e)
	s.ServiceAccounts.Register(e)
	s.administrationRoutes(e)
	s.Impersonation.Register(e)
	s.OAuth.RegisterManagement(e)
	s.Federation.Register(e)
	s.ProvisioningControl.Register(e)
	if s.Delivery != nil {
		s.Delivery.Register(e)
	}
}
