// Package auditloghttp serves the app audit log
// (…/environments/:environment/audit-logs/…).
package auditloghttp

import (
	"bufio"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Events serves the events: emit, list, find and export.
type Events struct {
	commands auditlog.EventCommands
	queries  auditlog.EventQueries
}

func NewEvents(commands auditlog.EventCommands, queries auditlog.EventQueries) *Events {
	return &Events{commands: commands, queries: queries}
}

// Register mounts the routes under /audit-logs/events of r. The export
// route comes before /:id.
func (h *Events) Register(r fiber.Router) { h.Routes(r.Group("/audit-logs/events")) }

// Routes mounts the routes on an /audit-logs/events group (the /api/v1
// one carries its permission check).
func (h *Events) Routes(r fiber.Router) {
	r.Post("/", h.Emit)
	r.Get("/", h.List)
	r.Get("/export", h.Export)
	r.Get("/:id", h.Find)
}

func environment(c *fiber.Ctx) (identity.EnvironmentID, error) {
	id, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return id, errx.Validation("environment must be a valid UUID")
	}
	return id, nil
}

// Emit stores one event. Header: Idempotency-Key (at most 255 characters).
// The same key with the same request answers the first event's 201 again;
// another request is 409 IDEMPOTENCY_KEY_REUSED.
func (h *Events) Emit(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	if len(c.Body()) > config.AuditLogMaxBody {
		return auditlog.ErrBodyTooLarge()
	}
	var input auditlog.Input
	if err := c.BodyParser(&input); err != nil {
		return errx.Validation("invalid request body")
	}
	out, err := h.commands.Emit(c.UserContext(), env, input, c.Get("Idempotency-Key"))
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// List reads the log. Query: organization_id, action (repeatable or
// comma-separated), actor_id, actor_type, target_id, target_type,
// occurred_after, occurred_before (RFC 3339), after (oldest first from
// that seq; 0 = the beginning) or before (newest first below that seq),
// limit (≤ 200).
func (h *Events) List(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	filter, err := Filter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.List(c.UserContext(), env, filter, c.QueryInt("limit"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Events) Find(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	id, err := identity.ParseAuditEventID(c.Params("id"))
	if err != nil {
		return auditlog.ErrEventNotFound()
	}
	out, err := h.queries.Find(c.UserContext(), env, id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Filter parses the log query parameters.
func Filter(c *fiber.Ctx) (auditlog.Filter, error) {
	var f auditlog.Filter
	for _, raw := range c.Context().QueryArgs().PeekMulti("action") {
		for _, a := range strings.Split(string(raw), ",") {
			if a = strings.TrimSpace(a); a != "" {
				f.Actions = append(f.Actions, a)
			}
		}
	}
	f.ActorID, f.ActorType = c.Query("actor_id"), c.Query("actor_type")
	f.TargetID, f.TargetType = c.Query("target_id"), c.Query("target_type")
	if raw := c.Query("organization_id"); raw != "" {
		org, err := identity.ParseOrganizationID(raw)
		if err != nil {
			return f, errx.Validation("organization_id must be a valid UUID")
		}
		f.Organization = org
	}
	var err error
	if f.OccurredAfter, err = instant(c.Query("occurred_after"), "occurred_after"); err != nil {
		return f, err
	}
	if f.OccurredBefore, err = instant(c.Query("occurred_before"), "occurred_before"); err != nil {
		return f, err
	}
	if raw := c.Query("after"); raw != "" {
		after, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return f, errx.Validation("after must be an event cursor")
		}
		f.After = &after
	}
	if raw := c.Query("before"); raw != "" {
		before, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return f, errx.Validation("before must be an event cursor")
		}
		f.Before = before
	}
	return f, nil
}

func instant(raw, name string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, errx.Validation(name + " must be an RFC 3339 timestamp")
	}
	return &t, nil
}

// Export streams the matching events oldest first (from after, default the
// beginning, to the newest) as NDJSON (one event per line) or CSV. Query:
// format (ndjson, default, or csv) and the filters of the log, without
// before. CSV cells that start with = + - @ gain a leading ' so a
// spreadsheet never reads them as formulas.
func (h *Events) Export(c *fiber.Ctx) error {
	env, err := environment(c)
	if err != nil {
		return err
	}
	filter, err := Filter(c)
	if err != nil {
		return err
	}
	if filter.Before != 0 {
		return errx.Validation("export reads forward: use after, not before")
	}
	if err := filter.Validate(); err != nil {
		return err
	}
	format := c.Query("format", auditlog.FormatNDJSON)
	if !auditlog.ValidFormat(format) {
		return errx.Validation("format must be ndjson or csv")
	}
	// The body is written after the handler returns: detach from the
	// request context (keeping its values: trace, request id).
	ctx := context.WithoutCancel(c.UserContext())
	// The type depends on the format, so the generator documents the body
	// without a media type check.
	contentType, name := auditlog.ExportHeaders(format)
	c.Set(fiber.HeaderContentType, contentType)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="`+name+`"`)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		write := auditlog.Encoder(w, format)
		// A write error means the client left: stop reading. A read error
		// cuts the body short; it can only be logged once streaming began.
		failed := false
		err := h.queries.Export(ctx, env, filter, func(e auditlog.Event) error {
			if err := write(e); err != nil {
				failed = true
				return err
			}
			if w.Buffered() > 64<<10 {
				if err := w.Flush(); err != nil {
					failed = true
					return err
				}
			}
			return nil
		})
		if err != nil && !failed {
			slog.ErrorContext(ctx, "audit log export cut short", "error", err)
		}
		_ = w.Flush()
	})
	return nil
}
