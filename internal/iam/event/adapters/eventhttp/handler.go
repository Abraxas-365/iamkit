// Package eventhttp serves the event log
// (GET …/environments/:environment/events).
package eventhttp

import (
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

type Handler struct{ queries event.Queries }

func New(queries event.Queries) *Handler { return &Handler{queries} }

func (h *Handler) Register(r fiber.Router) { r.Get("/events", h.List) }

// List reads the log. Query: type (comma-separated types or families
// such as user.*; repeatable), subject, organization_id, after (oldest
// first from that id; 0 = the beginning) or before (newest first below
// that id), limit (≤ 200).
func (h *Handler) List(c *fiber.Ctx) error {
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return errx.Validation("environment must be a valid UUID")
	}
	filter, err := Filter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.List(c.UserContext(), environment, filter, c.QueryInt("limit"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Filter parses the log query parameters.
func Filter(c *fiber.Ctx) (event.Filter, error) {
	var f event.Filter
	for _, raw := range c.Context().QueryArgs().PeekMulti("type") {
		for _, t := range strings.Split(string(raw), ",") {
			if t = strings.TrimSpace(t); t != "" {
				f.Types = append(f.Types, t)
			}
		}
	}
	f.Subject = c.Query("subject")
	if raw := c.Query("organization_id"); raw != "" {
		org, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return f, errx.Validation("organization_id must be a valid UUID")
		}
		f.Organization = org
	}
	if raw := c.Query("after"); raw != "" {
		after, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return f, errx.Validation("after must be an event id")
		}
		f.After = &after
	}
	if raw := c.Query("before"); raw != "" {
		before, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return f, errx.Validation("before must be an event id")
		}
		f.Before = before
	}
	return f, nil
}
