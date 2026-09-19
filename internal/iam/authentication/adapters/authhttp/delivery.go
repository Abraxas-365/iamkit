package authhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authsvc"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type DeliveryHandler struct {
	service *authsvc.DeliveryService
}

func NewDeliveryHandler(s *authsvc.DeliveryService) *DeliveryHandler {
	return &DeliveryHandler{service: s}
}
func (h *DeliveryHandler) Register(e fiber.Router) {
	e.Get("/delivery", h.Get)
	e.Put("/delivery", h.Set)
	e.Delete("/delivery", h.Delete)
}
func envParam(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}
func (h *DeliveryHandler) Get(c *fiber.Ctx) error {
	cfg, err := h.service.DeliveryConfig(c.Context(), envParam(c))
	if err != nil {
		return err
	}
	return c.JSON(cfg)
}
func (h *DeliveryHandler) Set(c *fiber.Ctx) error {
	var input authentication.DeliveryConfigInput
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	if err := h.service.SetDeliveryConfig(c.Context(), envParam(c), input); err != nil {
		return err
	}
	return c.SendStatus(204)
}
func (h *DeliveryHandler) Delete(c *fiber.Ctx) error {
	if err := h.service.DeleteDeliveryConfig(c.Context(), envParam(c)); err != nil {
		return err
	}
	return c.SendStatus(204)
}
