// Package actionmodule assembles actions' concrete adapters.
// It is imported only by the composition root.
package actionmodule

import (
	"context"
	"github.com/Abraxas-365/iamkit/internal/cache"
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/action/actionsvc"
	"github.com/Abraxas-365/iamkit/internal/iam/action/adapters/actionhook"
	"github.com/Abraxas-365/iamkit/internal/iam/action/adapters/actionhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/action/adapters/actionpg"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Cipher seals target secrets (IAMKIT_ENCRYPTION_KEY).
	Cipher action.Cipher
	// Transport reaches targets (nil: public addresses only).
	Transport http.RoundTripper
	// Features turns actions off per environment (nil: always on).
	Features action.Features
	// Usage limits and counts target calls (nil: none).
	Usage action.Usage
	// Cache keeps condition bindings (REDIS_URL; nil: none).
	Cache   cache.Store
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands action.Commands
	Queries  action.Queries
	// Runner is what flows call at their conditions.
	Runner action.Runner
	HTTP   *actionhttp.Handler
	// Jobs prunes the recent-calls log.
	Jobs []worker.Job
}

func New(deps Deps) Module {
	service := actionsvc.New(actionpg.New(deps.DB), actionhook.Caller{Transport: deps.Transport}, deps.Cipher, actionhook.Secrets{}, deps.Features)
	if deps.Usage != nil {
		service.SetUsage(deps.Usage)
	}
	service.SetCache(deps.Cache)
	return Module{Commands: service, Queries: service, Runner: service, HTTP: actionhttp.New(service, service, deps.ActorID),
		Jobs: []worker.Job{{Name: "action_call_prune", Interval: time.Hour, Run: func(ctx context.Context) (bool, error) { return false, service.PruneCalls(ctx) }}}}
}
