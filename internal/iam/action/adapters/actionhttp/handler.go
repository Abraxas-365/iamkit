// Package actionhttp serves actions under
// /management/v1/environments/:environment: targets (/action-targets),
// executions (/action-executions/:condition, the condition URL-encoded or
// written with "." for ":"), the condition catalog (/action-conditions)
// and the recent-calls log (/action-calls).
package actionhttp

import (
	"net/url"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	commands action.Commands
	queries  action.Queries
	actor    func(*fiber.Ctx) string
}

func New(commands action.Commands, queries action.Queries, actor func(*fiber.Ctx) string) *Handler {
	return &Handler{commands: commands, queries: queries, actor: actor}
}

func env(c *fiber.Ctx) identity.EnvironmentID {
	id, _ := identity.ParseEnvironmentID(c.Params("environment"))
	return id
}

// Register mounts the routes under an environment router.
func (h *Handler) Register(e fiber.Router) {
	e.Get("/action-conditions", h.conditions)
	e.Get("/action-targets", h.listTargets)
	e.Post("/action-targets", h.createTarget)
	e.Get("/action-targets/:id", h.findTarget)
	e.Patch("/action-targets/:id", h.updateTarget)
	e.Delete("/action-targets/:id", h.deleteTarget)
	e.Post("/action-targets/:id/rotate-secret", h.rotateSecret)
	e.Post("/action-targets/:id/test", h.testTarget)
	e.Get("/action-executions", h.listExecutions)
	e.Put("/action-executions/:condition", h.setExecution)
	e.Delete("/action-executions/:condition", h.deleteExecution)
	e.Get("/action-calls", h.listCalls)
}

func (h *Handler) mutation(c *fiber.Ctx, verb string) action.Mutation {
	return action.Mutation{Environment: env(c), Actor: h.actor(c), Action: verb}
}

func target(c *fiber.Ctx) (identity.TargetID, error) {
	id, err := identity.ParseTargetID(c.Params("id"))
	if err != nil {
		return id, errx.NotFound("action target not found")
	}
	return id, nil
}

// condition reads the :condition parameter: function:pre_sign_in
// (URL-encoded) or function.pre_sign_in.
func condition(c *fiber.Ctx) string {
	raw, err := url.PathUnescape(c.Params("condition"))
	if err != nil {
		return ""
	}
	if kind, name, ok := strings.Cut(raw, "."); ok && !strings.Contains(raw, ":") && (kind == "function" || kind == "request") {
		return kind + ":" + name
	}
	return raw
}

func (h *Handler) conditions(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"items": action.Conditions})
}

func (h *Handler) listTargets(c *fiber.Ctx) error {
	out, err := h.queries.ListTargets(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) createTarget(c *fiber.Ctx) error {
	var input action.TargetCreate
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.CreateTarget(c.UserContext(), h.mutation(c, action.ActionTargetCreate), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) findTarget(c *fiber.Ctx) error {
	id, err := target(c)
	if err != nil {
		return err
	}
	out, err := h.queries.FindTarget(c.UserContext(), env(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) updateTarget(c *fiber.Ctx) error {
	id, err := target(c)
	if err != nil {
		return err
	}
	var input action.TargetUpdate
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.UpdateTarget(c.UserContext(), h.mutation(c, action.ActionTargetUpdate), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteTarget(c *fiber.Ctx) error {
	id, err := target(c)
	if err != nil {
		return err
	}
	if err = h.commands.DeleteTarget(c.UserContext(), h.mutation(c, action.ActionTargetDelete), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) rotateSecret(c *fiber.Ctx) error {
	id, err := target(c)
	if err != nil {
		return err
	}
	out, err := h.commands.RotateTargetSecret(c.UserContext(), h.mutation(c, action.ActionTargetRotate), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) testTarget(c *fiber.Ctx) error {
	id, err := target(c)
	if err != nil {
		return err
	}
	var input action.Test
	if err = c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.TestTarget(c.UserContext(), env(c), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) listExecutions(c *fiber.Ctx) error {
	out, err := h.queries.ListExecutions(c.UserContext(), env(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) setExecution(c *fiber.Ctx) error {
	var input action.ExecutionSet
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request")
	}
	out, err := h.commands.SetExecution(c.UserContext(), h.mutation(c, action.ActionExecutionSet), condition(c), input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteExecution(c *fiber.Ctx) error {
	if err := h.commands.DeleteExecution(c.UserContext(), h.mutation(c, action.ActionExecutionDelete), condition(c)); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) listCalls(c *fiber.Ctx) error {
	filter := action.CallFilter{Condition: c.Query("condition"), Outcome: c.Query("outcome")}
	if raw := c.Query("target_id"); raw != "" {
		id, err := identity.ParseTargetID(raw)
		if err != nil {
			return errx.Validation("target_id must be a valid UUID")
		}
		filter.Target = &id
	}
	out, err := h.queries.ListCalls(c.UserContext(), env(c), filter, c.QueryInt("limit", 50))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}
