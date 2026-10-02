// Package eventmodule assembles the event log's concrete adapters.
// It is imported only by the composition root.
package eventmodule

import (
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/event"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventhook"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/event/adapters/eventpg"
	"github.com/Abraxas-365/iamkit/internal/iam/event/eventsvc"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Retention is how long events are kept (IAMKIT_EVENT_RETENTION).
	Retention time.Duration
	// Cipher seals webhook secrets (IAMKIT_ENCRYPTION_KEY).
	Cipher event.Cipher
	// Transport reaches webhook endpoints (nil: public addresses only).
	Transport http.RoundTripper
	ActorID   func(*fiber.Ctx) string
}

type Module struct {
	Queries  event.Queries
	Commands event.Commands
	HTTP     *eventhttp.Handler
	// Webhooks serves event webhook subscriptions.
	Webhooks *eventhttp.Subscriptions
	// Dispatcher sends one round of due webhook deliveries now (tests).
	Dispatcher event.Dispatcher
	// Jobs prunes events past the retention, delivers webhooks and
	// maintains subscriptions.
	Jobs []worker.Job
}

func New(deps Deps) Module {
	service := eventsvc.New(eventpg.New(deps.DB), deps.Retention)
	hooks := eventsvc.NewSubscriptions(eventpg.NewSubscriptions(deps.DB), eventhook.Sender{Transport: deps.Transport}, deps.Cipher, eventhook.Secrets{})
	return Module{Queries: service, Commands: service, HTTP: eventhttp.New(service),
		Webhooks: eventhttp.NewSubscriptions(hooks, hooks, deps.ActorID), Dispatcher: hooks, Jobs: []worker.Job{
			{Name: "event_prune", Interval: time.Hour, Run: service.Prune},
			{Name: "event_webhook", Interval: config.EventWebhookInterval, Run: hooks.DispatchRound, Lag: hooks.Lag},
			{Name: "event_webhook_maintenance", Interval: 10 * time.Minute, Run: hooks.Maintain},
		}}
}
