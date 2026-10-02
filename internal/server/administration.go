package server

import "github.com/gofiber/fiber/v2"

func (s *Server) administrationRoutes(e fiber.Router) {
	s.Activity.Register(e)
	if s.Events != nil {
		s.Events.Register(e)
		s.Events.RegisterHistory(e)
	}
	if s.Webhooks != nil {
		s.Webhooks.Register(e)
	}
	s.Grants.Register(e)
	org := e.Group("/organizations/:organization", s.Structure.Check)
	s.Structure.RegisterViews(org)
	s.Structure.RegisterMutations(org)
	if s.Groups != nil {
		s.Groups.RegisterViews(org)
		s.Groups.RegisterMutations(org)
	}
	if s.Domains != nil {
		s.Domains.RegisterViews(org)
		s.Domains.RegisterMutations(org)
	}
	if s.Invitations != nil {
		s.Invitations.RegisterViews(org)
		s.Invitations.RegisterMutations(org)
	}
}
