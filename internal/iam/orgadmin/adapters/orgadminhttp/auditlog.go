package orgadminhttp

import (
	"bufio"
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/httpx"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/authorization"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// auditFilter parses the log query parameters the organization's
// administrators may use: those of the environment's log without
// organization_id, which is always the principal's.
func auditFilter(c *fiber.Ctx) (auditlog.Filter, error) {
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

// auditLogs lists the organization's app audit log events. Query: action
// (repeatable or comma-separated), actor_id, actor_type, target_id,
// target_type, occurred_after, occurred_before (RFC 3339), after (oldest
// first from that seq) or before (newest first below it), limit (≤ 200).
func (h *Handler) auditLogs(c *fiber.Ctx) error {
	filter, err := auditFilter(c)
	if err != nil {
		return err
	}
	out, err := h.queries.AuditLogs(c.UserContext(), principal(c), filter, c.QueryInt("limit"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// exportAuditLogs streams the organization's events oldest first as NDJSON
// or CSV (query format, default ndjson; the filters of the list, without
// before).
func (h *Handler) exportAuditLogs(c *fiber.Ctx) error {
	p := principal(c)
	// The permission is checked before the body streams: the stream
	// itself answers after the handler returned.
	if err := p.Require(authorization.PermOrgAuditRead); err != nil {
		return err
	}
	filter, err := auditFilter(c)
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
	contentType, name := auditlog.ExportHeaders(format)
	c.Set(fiber.HeaderContentType, contentType)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="`+name+`"`)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		write := auditlog.Encoder(w, format)
		// A write error means the client left: stop reading. A read error
		// cuts the body short; it can only be logged once streaming began.
		failed := false
		err := h.queries.ExportAuditLogs(ctx, p, filter, func(e auditlog.Event) error {
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

func streamID(c *fiber.Ctx) (identity.LogStreamID, error) {
	id, err := identity.ParseLogStreamID(c.Params("stream"))
	if err != nil {
		return id, errx.NotFound("log stream not found")
	}
	return id, nil
}

func (h *Handler) logStreams(c *fiber.Ctx) error {
	out, err := h.queries.LogStreams(c.UserContext(), principal(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"items": out})
}

func (h *Handler) logStream(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.LogStream(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// createLogStream answers 201; an https stream's signing secret is shown
// once. Sources are always audit_logs.
func (h *Handler) createLogStream(c *fiber.Ctx) error {
	var input logstream.Create
	if err := body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.CreateLogStream(c.UserContext(), principal(c), input)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) updateLogStream(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	var input logstream.Update
	if err = body(c, &input); err != nil {
		return err
	}
	out, err := h.commands.UpdateLogStream(c.UserContext(), principal(c), id, input)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) enableLogStream(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.EnableLogStream(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func (h *Handler) deleteLogStream(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	return done(c, h.commands.DeleteLogStream(c.UserContext(), principal(c), id))
}

func (h *Handler) rotateLogStream(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.RotateLogStreamSecret(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// testLogStream sends one synthetic record now and answers with the outcome.
func (h *Handler) testLogStream(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	out, err := h.commands.TestLogStream(c.UserContext(), principal(c), id)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// logStreamDeliveries reads the delivery log. Query: status (pending,
// delivered, failed), limit, offset.
func (h *Handler) logStreamDeliveries(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	out, err := h.queries.LogStreamDeliveries(c.UserContext(), principal(c), id, logstream.DeliveryFilter{Status: c.Query("status")}, httpx.PaginationFromCtx(c))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// retryLogStreamDelivery queues a failed delivery's batch again.
func (h *Handler) retryLogStreamDelivery(c *fiber.Ctx) error {
	id, err := streamID(c)
	if err != nil {
		return err
	}
	delivery, err := strconv.ParseInt(c.Params("delivery"), 10, 64)
	if err != nil || delivery <= 0 {
		return errx.NotFound("failed log stream delivery not found")
	}
	if err := h.commands.RetryLogStreamDelivery(c.UserContext(), principal(c), id, delivery); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusAccepted)
}
