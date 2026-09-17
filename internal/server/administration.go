package server

import "github.com/gofiber/fiber/v2"

func (s *Server) administrationRoutes(e fiber.Router) {
	s.Activity.Register(e)
	s.Grants.Register(e)
	s.Structure.Register(e)
}
