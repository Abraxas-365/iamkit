// Package logstreammodule assembles the log streams' concrete adapters.
// It is imported only by the composition root.
package logstreammodule

import (
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/blob"
	"github.com/Abraxas-365/iamkit/internal/blob/adapters/gocloudblob"
	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/logstreamhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/logstreampg"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lsdatadog"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lshttps"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lss3"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/adapters/lssplunk"
	"github.com/Abraxas-365/iamkit/internal/iam/logstream/logstreamsvc"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Cipher seals stream secrets (IAMKIT_ENCRYPTION_KEY).
	Cipher logstream.Cipher
	// Transport reaches destinations and S3 endpoints (nil: public
	// addresses only).
	Transport http.RoundTripper
	// Blobs replaces the S3 opener (tests).
	Blobs   blob.Opener
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands logstream.Commands
	Queries  logstream.Queries
	HTTP     *logstreamhttp.Handler
	// Dispatcher sends one round of due batches now (tests).
	Dispatcher logstream.Dispatcher
	// Jobs delivers batches and maintains streams.
	Jobs []worker.Job
}

func New(deps Deps) Module {
	opener := deps.Blobs
	if opener == nil {
		opener = gocloudblob.Opener{Transport: deps.Transport}
	}
	sender := logstream.Senders{
		logstream.DestinationDatadog: lsdatadog.Sender{Transport: deps.Transport},
		logstream.DestinationSplunk:  lssplunk.Sender{Transport: deps.Transport},
		logstream.DestinationHTTPS:   lshttps.Sender{Transport: deps.Transport},
		logstream.DestinationS3:      lss3.Sender{Opener: opener},
	}
	service := logstreamsvc.New(logstreampg.New(deps.DB), sender, deps.Cipher, lshttps.Secrets{})
	return Module{Commands: service, Queries: service, HTTP: logstreamhttp.New(service, service, deps.ActorID), Dispatcher: service, Jobs: []worker.Job{
		{Name: "log_stream_delivery", Interval: config.LogStreamInterval, Run: service.DispatchRound, Lag: service.Lag},
		{Name: "log_stream_maintenance", Interval: 10 * time.Minute, Run: service.Maintain},
	}}
}
