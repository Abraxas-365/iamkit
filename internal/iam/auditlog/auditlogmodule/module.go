// Package auditlogmodule assembles the app audit log's concrete adapters.
// It is imported only by the composition root.
package auditlogmodule

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/auditlog"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog/adapters/auditloghttp"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog/adapters/auditlogpg"
	"github.com/Abraxas-365/iamkit/internal/iam/auditlog/auditlogsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userschema"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Retention is how long events are kept (IAMKIT_AUDIT_LOG_RETENTION).
	Retention time.Duration
	// Schemas compiles and applies the actions' JSON Schemas (default: the
	// userschema validator, the same draft 2020-12 rules as user schemas).
	Schemas auditlog.SchemaValidator
	// Usage limits and counts ingest (nil: none).
	Usage   auditlog.Usage
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	// EventCommands emit events; EventQueries read the log, filtered by
	// organization (organization administrators read through it).
	EventCommands auditlog.EventCommands
	EventQueries  auditlog.EventQueries
	ActionQueries auditlog.ActionQueries
	// Events and Actions serve …/audit-logs/events and …/audit-logs/actions.
	Events  *auditloghttp.Events
	Actions *auditloghttp.Actions
	// Jobs prunes events past the retention.
	Jobs []worker.Job
}

func New(deps Deps) Module {
	if deps.Schemas == nil {
		deps.Schemas = userschema.Validator{}
	}
	actionRepository := auditlogpg.NewActions(deps.DB)
	actions := auditlogsvc.NewActions(actionRepository, deps.Schemas)
	events := auditlogsvc.New(auditlogpg.NewEvents(deps.DB), actionRepository, deps.Schemas, deps.Retention)
	if deps.Usage != nil {
		events.SetUsage(deps.Usage)
	}
	return Module{EventCommands: events, EventQueries: events, ActionQueries: actions,
		Events: auditloghttp.NewEvents(events, events), Actions: auditloghttp.NewActions(actions, actions, deps.ActorID),
		Jobs: []worker.Job{{Name: "audit_log_prune", Interval: time.Hour, Run: func(ctx context.Context) (bool, error) { return events.Prune(ctx) }}}}
}
