package risk

import (
	"context"
	"time"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Request is what the HTTP layer knows about a sign-in request beyond
// identity.ClientInfo: the surface, the device id (hosted cookie
// __Host-iamkit-device or headless device_id) and the CAPTCHA outcome. It
// travels in the context (WithRequest) so sign-in services need no new
// parameters.
type Request struct {
	Surface string
	// Device is the raw device id ("" = none: new_device is not
	// evaluated). Stored only as a hash.
	Device string
	// Captcha is CaptchaPassed / CaptchaUnavailable ("" = not required).
	Captcha string
}

// MaxDeviceID bounds a device id.
const MaxDeviceID = 128

// ValidDevice reports whether a client-sent device id is usable: 16–128
// printable ASCII characters (clients/js sends 32 hex characters).
func ValidDevice(id string) bool {
	if len(id) < 16 || len(id) > MaxDeviceID {
		return false
	}
	for _, r := range id {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

type requestKey struct{}

// WithRequest returns ctx carrying r (an invalid device id is dropped).
func WithRequest(ctx context.Context, r Request) context.Context {
	if !ValidDevice(r.Device) {
		r.Device = ""
	}
	return context.WithValue(ctx, requestKey{}, r)
}

// RequestFrom returns the Request WithRequest stored; without one the
// surface is headless.
func RequestFrom(ctx context.Context) Request {
	r, ok := ctx.Value(requestKey{}).(Request)
	if !ok || r.Surface == "" {
		r.Surface = SurfaceHeadless
	}
	return r
}

type decisionKey struct{}

// WithDecision carries the decision of the sign-in being finished in the
// context, so the session writer (country, risk_detections) and the
// pre_sign_in hook (Input.Risk) need no new parameters.
func WithDecision(ctx context.Context, d Decision) context.Context {
	return context.WithValue(ctx, decisionKey{}, d)
}

// DecisionFrom returns the decision WithDecision stored.
func DecisionFrom(ctx context.Context) (Decision, bool) {
	d, ok := ctx.Value(decisionKey{}).(Decision)
	return d, ok
}

// Signal is one sign-in attempt as the sign-in services describe it to
// risk evaluation. The client (IP, User-Agent, country) and the Request
// come from the context.
type Signal struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	// User is the identified account (zero when unknown or not yet
	// identified).
	User identity.UserID
	// Login is what was typed (email or username; "" for passkeys and
	// federation). Only its keyed hash is stored.
	Login string
	// Method is authentication.MethodPassword / MethodCode /
	// MethodPasskey / MethodSSO, or "signup".
	Method string
	// MFA: the first factor is multi-factor (passkey) or the session will
	// carry a second factor; EmailProof: the first factor proved the
	// inbox (email code). Either satisfies a challenge.
	MFA        bool
	EmailProof bool
	// Email is the identified account's address (Assess): email domain
	// restrictions then also apply to sign-ins by username, passkey, code
	// or federation, whose Login is not that address.
	Email string
}

// MethodSignup is the Signal.Method of a self-service signup (screened by
// restrictions only).
const MethodSignup = "signup"

// Decision is what risk evaluation decided for a sign-in.
type Decision struct {
	// Action is the strongest action of the detections (ActionNone when
	// nothing was detected or every detection is off).
	Action     string   `json:"action"`
	Detections []string `json:"detections"`
	// Allowed: an allow restriction matched; detections were skipped.
	Allowed bool `json:"allowed,omitempty"`
	// SatisfiedBy names why a challenge was not asked: "mfa" (a second
	// factor runs), "email_proof", "passkey", "unverifiable".
	SatisfiedBy string `json:"satisfied_by,omitempty"`
	DeviceKnown bool   `json:"device_known"`
	Counts      Counts `json:"counts"`
	Country     string `json:"country,omitempty"`
	// Challenged: the decision comes back after a completed challenge.
	Challenged bool `json:"challenge_completed,omitempty"`
	// Notify lists the detections whose action is notify while the policy
	// notifies users: Record emails them after a successful sign-in.
	Notify []string `json:"-"`
	// Off: risk evaluation did not run (flag off, nothing configured);
	// pre_sign_in then gets no risk input and the session no detections.
	Off bool `json:"-"`
	// BlockIfUnverifiable carries the policy's setting for Resolve.
	BlockIfUnverifiable bool `json:"-"`
	// Restricted: a deny restriction matched the account's email (Action
	// is block; the attempt's reason is restriction, not detection).
	Restricted bool `json:"-"`
}

// Challenge reports whether the sign-in must answer an emailed code.
func (d Decision) Challenge() bool { return d.Action == ActionChallenge && d.SatisfiedBy == "" }

// Block reports whether the sign-in is refused.
func (d Decision) Block() bool { return d.Action == ActionBlock }

// Alert is a security_alert email to the user (action notify).
type Alert struct {
	Environment identity.EnvironmentID
	User        identity.UserID
	Detection   string
	IP          string
	Country     string
	UserAgent   string
	At          time.Time
	Locale      string
}

// Resolve applies what the sign-in service knows after the first factor:
// whether a second factor runs anyway (mfa), the first factor already
// proved the inbox (emailProof) and whether the user has a verified email
// to receive the challenge. A challenge nothing can ask for is satisfied
// (SatisfiedBy) or, with BlockIfUnverifiable, becomes a block.
func (d Decision) Resolve(mfa, emailProof, verifiedEmail bool) Decision {
	if d.Action != ActionChallenge || d.SatisfiedBy != "" {
		return d
	}
	switch {
	case mfa:
		d.SatisfiedBy = "mfa"
	case emailProof:
		d.SatisfiedBy = "email_proof"
	case !verifiedEmail && d.BlockIfUnverifiable:
		d.Action = ActionBlock
	case !verifiedEmail:
		d.SatisfiedBy = "unverifiable"
	}
	return d
}
