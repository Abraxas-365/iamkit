// Package risksvc implements bot protection (CAPTCHA) and risk signals:
// the CAPTCHA configuration and verification (captcha.go, W2), the risk
// policy and restrictions (policy.go), the attempt log (attempts.go) and
// sign-in evaluation (evaluate.go).
package risksvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
)

var (
	_ risk.CaptchaCommands = (*Service)(nil)
	_ risk.CaptchaQueries  = (*Service)(nil)
	_ risk.PolicyCommands  = (*Service)(nil)
	_ risk.PolicyQueries   = (*Service)(nil)
	_ risk.AttemptCommands = (*Service)(nil)
	_ risk.AttemptQueries  = (*Service)(nil)
	_ risk.Evaluator       = (*Service)(nil)
)

// Deps are the service's collaborators. Cipher, Geo and Notifier may be
// nil: no CAPTCHA secret can be stored, no GeoIP, no alert emails.
type Deps struct {
	Captchas risk.CaptchaRepository
	Policies risk.PolicyRepository
	Attempts risk.AttemptRepository
	Verifier risk.Verifier
	Geo      risk.Geo
	Notifier risk.Notifier
	Cipher   risk.Cipher
	Features risk.Features
	Keys     risk.Keys
	// IssuerHost is the host name of the issuer URL: hosted CAPTCHA
	// tokens must have been solved on it (headless ones may be too).
	IssuerHost string
	// OnError counts an evaluation that failed open (the module wires
	// telemetry.RiskError); nil: only logged.
	OnError func(ctx context.Context, stage string)
	// Retention is how long attempts are kept (default
	// config.SignInAttemptRetention).
	Retention time.Duration
}

// Service implements every risk use case.
type Service struct {
	captchas   risk.CaptchaRepository
	policies   risk.PolicyRepository
	attempts   risk.AttemptRepository
	verifier   risk.Verifier
	geo        risk.Geo
	notifier   risk.Notifier
	cipher     risk.Cipher
	features   risk.Features
	keys       risk.Keys
	issuerHost string
	onError    func(ctx context.Context, stage string)
	retention  time.Duration
	now        func() time.Time
}

func New(d Deps) *Service {
	if d.Retention <= 0 {
		d.Retention = config.SignInAttemptRetention
	}
	return &Service{captchas: d.Captchas, policies: d.Policies, attempts: d.Attempts, verifier: d.Verifier, geo: d.Geo, notifier: d.Notifier,
		cipher: d.Cipher, features: d.Features, keys: d.Keys, issuerHost: strings.ToLower(d.IssuerHost), onError: d.OnError, retention: d.Retention, now: time.Now}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }
