// Package riskmodule assembles bot protection and risk signals. It is
// imported only by the composition root.
package riskmodule

import (
	"context"
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/iam/risk/adapters/riskcaptcha"
	"github.com/Abraxas-365/iamkit/internal/iam/risk/adapters/riskgeo"
	"github.com/Abraxas-365/iamkit/internal/iam/risk/adapters/riskhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/risk/adapters/riskmail"
	"github.com/Abraxas-365/iamkit/internal/iam/risk/adapters/riskpg"
	"github.com/Abraxas-365/iamkit/internal/iam/risk/risksvc"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
	"github.com/Abraxas-365/iamkit/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Cipher seals CAPTCHA secrets (nil: none can be stored).
	Cipher   risk.Cipher
	Features risk.Features
	// Transport replaces the guarded transport of siteverify calls (tests).
	Transport http.RoundTripper
	// GeoIPDB / GeoIPHeader: the deployment's GeoIP (both empty = none).
	GeoIPDB     string
	GeoIPHeader string
	Retention   time.Duration
	// Mail sends security alerts (the authentication DeliveryService; nil:
	// no alert emails).
	Mail riskmail.Mail
	// Secret is the deployment secret login and device hashes are keyed
	// with (nil or empty: salted SHA-256 per environment, risksvc.HashKeys).
	Secret  func() string
	ActorID func(*fiber.Ctx) string
	// Issuer is the deployment's issuer URL: hosted CAPTCHA tokens must
	// have been solved on its host.
	Issuer string
}

// Module exposes risk evaluation to the sign-in modules (Evaluator, Captcha)
// and the HTTP surfaces.
type Module struct {
	Captcha   risk.CaptchaCommands
	Captchas  risk.CaptchaQueries
	Policy    risk.PolicyCommands
	Policies  risk.PolicyQueries
	Attempts  risk.AttemptQueries
	Evaluator risk.Evaluator
	HTTP      *riskhttp.Handler
	Public    *riskhttp.Public
	Jobs      []worker.Job
	// WaitAlerts waits for security alert emails still being sent.
	WaitAlerts func(timeout time.Duration) bool
}

func New(d Deps) Module {
	attempts := riskpg.NewAttempts(d.DB)
	captchas := riskpg.NewCaptchas(d.DB)
	var geo risk.Geo
	if g := riskgeo.New(d.GeoIPDB, d.GeoIPHeader); g != nil {
		geo = g
	}
	var notifier risk.Notifier
	waitAlerts := func(time.Duration) bool { return true }
	if d.Mail != nil {
		n := riskmail.New(riskpg.NewRecipients(d.DB), d.Mail)
		notifier, waitAlerts = n, n.Wait
	}
	service := risksvc.New(risksvc.Deps{Policies: riskpg.NewPolicies(d.DB), Attempts: attempts, Captchas: captchas,
		Verifier: riskcaptcha.Verifier{Transport: d.Transport}, IssuerHost: risksvc.HostOf(d.Issuer), Geo: geo, Notifier: notifier,
		Keys: risksvc.HashKeys{Secret: d.Secret}, OnError: telemetry.RiskError, Cipher: d.Cipher, Features: d.Features, Retention: d.Retention})
	return Module{
		Captcha: service, Captchas: service, Policy: service, Policies: service, Attempts: service, Evaluator: service,
		HTTP:   riskhttp.New(riskhttp.Deps{Captcha: service, Captchas: service, Policy: service, Policies: service, Attempts: service}, d.ActorID),
		Public: riskhttp.NewPublic(service),
		Jobs: []worker.Job{
			{Name: "sign_in_attempt_prune", Interval: time.Hour, Run: func(ctx context.Context) (bool, error) {
				n, err := service.Prune(ctx)
				return false, wrapPrune(n, err)
			}},
			// Expired hosted CAPTCHA passes.
			{Name: "captcha_pass_prune", Interval: time.Hour, Run: func(ctx context.Context) (bool, error) {
				_, err := captchas.PrunePasses(ctx, time.Now())
				return false, err
			}},
		},
		WaitAlerts: waitAlerts,
	}
}

func wrapPrune(_ int, err error) error { return err }
