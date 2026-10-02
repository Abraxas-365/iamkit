// Package usagemodule assembles limits and usage metering. It is imported
// only by the composition root.
package usagemodule

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/usage"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/adapters/usagehttp"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/adapters/usagememory"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/adapters/usagepg"
	"github.com/Abraxas-365/iamkit/internal/iam/usage/usagesvc"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Deployment holds IAMKIT_LIMITS.
	Deployment usage.Values
	// Window counts per-minute limits (nil: in memory, per replica).
	Window  usage.Window
	ActorID func(*fiber.Ctx) string
	Owner   func(*fiber.Ctx) bool
}

type Module struct {
	Commands usage.Commands
	Queries  usage.Queries
	HTTP     *usagehttp.Handler
	// Meter limits and counts API requests (on routes binding :environment).
	Meter fiber.Handler
	// Jobs roll sign-ins and created users up from the event log and
	// prune old usage.
	Jobs []worker.Job
}

func New(deps Deps) Module {
	window := deps.Window
	if window == nil {
		window = usagememory.New()
	}
	service := usagesvc.New(usagepg.New(deps.DB), window, deps.Deployment)
	return Module{Commands: service, Queries: service, HTTP: usagehttp.New(service, service, deps.ActorID, deps.Owner), Meter: usagehttp.Meter(service),
		Jobs: []worker.Job{
			{Name: "usage_rollup", Interval: time.Minute, Run: service.Rollup},
			{Name: "usage_prune", Interval: 24 * time.Hour, Run: func(ctx context.Context) (bool, error) { return false, service.Prune(ctx) }},
		}}
}
