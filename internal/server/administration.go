package server

import "github.com/gofiber/fiber/v2"

func (s *Server) administrationRoutes(e fiber.Router) {
	s.Activity.Register(e)
	s.Grants.Register(e)
	org := e.Group("/organizations/:organization", s.Structure.Check)
	s.Structure.RegisterViews(org)
	s.Structure.RegisterMutations(org)
	if s.Groups != nil {
		s.Groups.RegisterViews(org)
		s.Groups.RegisterMutations(org)
	}
}
