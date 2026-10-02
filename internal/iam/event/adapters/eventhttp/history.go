package eventhttp

import (
	"bufio"
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// Histories maps the path collection of an entity to its subject kind:
// GET …/<collection>/:id/history is that entity's change history.
var Histories = map[string]string{
	"users":         "user",
	"organizations": "organization",
	"applications":  "application",
	"oauth-clients": "oauth_client",
	"roles":         "role",
	"resources":     "resource",
}

// RegisterHistory mounts GET /<collection>/:id/history for every entity of
// Histories and GET /events/export (management; /api/v1 mounts them per
// permission with History and Export).
func (h *Handler) RegisterHistory(r fiber.Router) {
	for collection, kind := range Histories {
		r.Get("/"+collection+"/:id/history", h.History(kind))
	}
	r.Get("/events/export", h.Export)
}

// History serves one entity's events newest first (before pages back;
// type filters), the same envelope as the log. Updates of users,
// organizations, applications, OAuth clients, roles and resources carry
// data.changes: {"field": [old, new]}.
func (h *Handler) History(kind string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		environment, err := identity.ParseEnvironmentID(c.Params("environment"))
		if err != nil {
			return errx.Validation("environment must be a valid UUID")
		}
		filter, err := Filter(c)
		if err != nil {
			return err
		}
		if filter.After != nil {
			return errx.Validation("history reads newest first: use before")
		}
		filter.Subject, filter.SubjectKind = c.Params("id"), kind
		out, err := h.queries.List(c.UserContext(), environment, filter, c.QueryInt("limit"))
		if err != nil {
			return err
		}
		return c.JSON(out)
	}
}

// Export streams the matching events oldest first as NDJSON (one event
// per line), from after (default the beginning) to the newest, for
// archiving past the retention. The filters are the log's, without before.
func (h *Handler) Export(c *fiber.Ctx) error {
	environment, err := identity.ParseEnvironmentID(c.Params("environment"))
	if err != nil {
		return errx.Validation("environment must be a valid UUID")
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
	// The body is written after the handler returns: detach from the
	// request context (keeping its values: trace, request id).
	ctx := context.WithoutCancel(c.UserContext())
	c.Set(fiber.HeaderContentType, "application/x-ndjson")
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="events.ndjson"`)
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		enc := json.NewEncoder(w)
		// A write error means the client left: stop reading.
		_ = h.queries.Export(ctx, environment, filter, func(e event.Event) error {
			if err := enc.Encode(e); err != nil {
				return err
			}
			if w.Buffered() > 64<<10 {
				return w.Flush()
			}
			return nil
		})
		_ = w.Flush()
	})
	return nil
}
