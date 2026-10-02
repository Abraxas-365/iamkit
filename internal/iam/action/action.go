// Package action is IAMKit's actions: synchronous hooks an operator binds
// to conditions of the sign-in, token and management flows. A target is
// an HTTPS endpoint (signed per Standard Webhooks); an execution lists the
// targets a condition calls, in order. A target may deny the flow, add
// token claims or patch selected request fields, depending on the
// condition (Conditions).
package action

import (
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Target kinds.
const (
	// KindCall waits for the answer and applies it (deny, claims, patch).
	KindCall = "call"
	// KindWebhook waits for a 2xx answer and ignores its body.
	KindWebhook = "webhook"
	// KindAsync is sent in the background; it never changes or stops the
	// flow.
	KindAsync = "async"
)

// Limits.
const (
	MaxTargets = 20
	// MaxExecutionTargets caps the targets one condition calls.
	MaxExecutionTargets = 5
	// MaxDenyMessage caps the message a denial shows.
	MaxDenyMessage = 200
)

// SecretPrefix starts every target secret (Standard Webhooks).
const SecretPrefix = "whsec_"

// Audit actions.
const (
	ActionTargetCreate    = "action_target.create"
	ActionTargetUpdate    = "action_target.update"
	ActionTargetDelete    = "action_target.delete"
	ActionTargetRotate    = "action_target.rotate_secret"
	ActionExecutionSet    = "action_execution.set"
	ActionExecutionDelete = "action_execution.delete"
)

// Call outcomes.
const (
	OutcomeOK      = "ok"
	OutcomeDenied  = "denied"
	OutcomeFailed  = "failed"
	OutcomeSkipped = "skipped"
)

// Mutation is an audited change of targets or executions.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

type Target struct {
	ID          identity.TargetID      `json:"id" db:"id"`
	Environment identity.EnvironmentID `json:"environment_id" db:"environment_id"`
	Name        string                 `json:"name" db:"name"`
	URL         string                 `json:"url" db:"url"`
	Kind        string                 `json:"kind" db:"kind"`
	TimeoutMS   int                    `json:"timeout_ms" db:"timeout_ms"`
	// InterruptOnError stops the flow (ACTION_FAILED) when the target
	// fails; otherwise the flow goes on without its changes.
	InterruptOnError bool      `json:"interrupt_on_error" db:"interrupt_on_error"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// Timeout is the target's call timeout.
func (t Target) Timeout() time.Duration { return time.Duration(t.TimeoutMS) * time.Millisecond }

// TargetCreate registers an endpoint. TimeoutMS 0 is config.ActionTimeout.
type TargetCreate struct {
	Name             string `json:"name"`
	URL              string `json:"url"`
	Kind             string `json:"kind"`
	TimeoutMS        int    `json:"timeout_ms"`
	InterruptOnError bool   `json:"interrupt_on_error"`
}

// Normalize trims and fills defaults.
func (c TargetCreate) Normalize() TargetCreate {
	c.Name, c.URL = strings.TrimSpace(c.Name), strings.TrimSpace(c.URL)
	if c.Kind == "" {
		c.Kind = KindCall
	}
	if c.TimeoutMS == 0 {
		c.TimeoutMS = int(config.ActionTimeout / time.Millisecond)
	}
	return c
}

func (c TargetCreate) Validate() error {
	if err := validName(c.Name); err != nil {
		return err
	}
	if err := ValidEndpoint(c.URL); err != nil {
		return err
	}
	if err := validKind(c.Kind); err != nil {
		return err
	}
	if c.Kind == KindAsync && c.InterruptOnError {
		return errx.Validation("interrupt_on_error is not available for async targets")
	}
	return validTimeout(c.TimeoutMS)
}

// TargetUpdate changes the fields that are set.
type TargetUpdate struct {
	Name             *string `json:"name"`
	URL              *string `json:"url"`
	Kind             *string `json:"kind"`
	TimeoutMS        *int    `json:"timeout_ms"`
	InterruptOnError *bool   `json:"interrupt_on_error"`
}

// Normalize trims the strings that are set.
func (u TargetUpdate) Normalize() TargetUpdate {
	if u.Name != nil {
		v := strings.TrimSpace(*u.Name)
		u.Name = &v
	}
	if u.URL != nil {
		v := strings.TrimSpace(*u.URL)
		u.URL = &v
	}
	return u
}

func (u TargetUpdate) Validate() error {
	if u.Name != nil {
		if err := validName(*u.Name); err != nil {
			return err
		}
	}
	if u.URL != nil {
		if err := ValidEndpoint(*u.URL); err != nil {
			return err
		}
	}
	if u.Kind != nil {
		if err := validKind(*u.Kind); err != nil {
			return err
		}
	}
	if u.TimeoutMS != nil {
		return validTimeout(*u.TimeoutMS)
	}
	return nil
}

// Apply returns t with the update's fields; the result is checked again
// (an async target cannot interrupt).
func (u TargetUpdate) Apply(t Target) (Target, error) {
	if u.Name != nil {
		t.Name = *u.Name
	}
	if u.URL != nil {
		t.URL = *u.URL
	}
	if u.Kind != nil {
		t.Kind = *u.Kind
	}
	if u.TimeoutMS != nil {
		t.TimeoutMS = *u.TimeoutMS
	}
	if u.InterruptOnError != nil {
		t.InterruptOnError = *u.InterruptOnError
	}
	if t.Kind == KindAsync && t.InterruptOnError {
		return t, errx.Validation("interrupt_on_error is not available for async targets")
	}
	return t, nil
}

// TargetSecret is returned once, when a target is created or its secret
// rotated.
type TargetSecret struct {
	ID     identity.TargetID `json:"id"`
	Secret string            `json:"secret"`
}

// Bound is a target an execution calls, with its live sealed secrets
// (current first).
type Bound struct {
	Target
	Sealed []string
}

// Outbound is one hook call with opened secrets, for the Caller.
type Outbound struct {
	// ID is the webhook-id header (act_<random>).
	ID      string
	URL     string
	Secrets []string
	Timeout time.Duration
	Body    []byte
}

// Answer is what an endpoint answered: Status 0 when no response arrived
// (Error says why); Body is read up to config.ActionMaxResponse.
type Answer struct {
	Status int
	Body   []byte
	Error  string
}

// OK reports a 2xx answer.
func (a Answer) OK() bool { return a.Status >= 200 && a.Status < 300 && a.Error == "" }

// Execution binds a condition to its targets, called in order.
type Execution struct {
	Condition string              `json:"condition"`
	Targets   []identity.TargetID `json:"targets"`
	UpdatedAt time.Time           `json:"updated_at"`
}

// ExecutionSet replaces a condition's targets.
type ExecutionSet struct {
	Targets []identity.TargetID `json:"targets"`
}

func (s ExecutionSet) Validate() error {
	if len(s.Targets) == 0 || len(s.Targets) > MaxExecutionTargets {
		return errx.Validation("targets must list 1 to 5 targets")
	}
	for i, t := range s.Targets {
		if t.IsZero() || slices.Contains(s.Targets[:i], t) {
			return errx.Validation("targets must be distinct target ids")
		}
	}
	return nil
}

// Call is one entry of the recent-calls log.
type Call struct {
	ID          int64                  `json:"id" db:"id"`
	Environment identity.EnvironmentID `json:"-" db:"-"`
	Target      identity.TargetID      `json:"target_id" db:"target_id"`
	Condition   string                 `json:"condition" db:"condition"`
	Outcome     string                 `json:"outcome" db:"outcome"`
	Status      *int                   `json:"status,omitempty" db:"status"`
	DurationMS  int                    `json:"duration_ms" db:"duration_ms"`
	Error       string                 `json:"error,omitempty" db:"error"`
	// Interrupted: the failure stopped the flow (interrupt_on_error).
	Interrupted bool      `json:"-" db:"-"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// CallFilter narrows the calls log; zero matches all.
type CallFilter struct {
	Target    *identity.TargetID
	Condition string
	Outcome   string
}

func (f CallFilter) Validate() error {
	switch f.Outcome {
	case "", OutcomeOK, OutcomeDenied, OutcomeFailed, OutcomeSkipped:
	default:
		return errx.Validation("outcome must be ok, denied, failed or skipped")
	}
	if f.Condition != "" {
		if _, ok := FindCondition(f.Condition); !ok {
			return ErrUnknownCondition()
		}
	}
	return nil
}

// Test calls a target once with a sample input, outside any flow.
type Test struct {
	Condition string `json:"condition"`
	Input     Input  `json:"input"`
}

func (t Test) Validate() error {
	if _, ok := FindCondition(t.Condition); !ok {
		return ErrUnknownCondition()
	}
	return nil
}

// TestResult is what a test call answered, checked like a real call.
type TestResult struct {
	Outcome    string   `json:"outcome"`
	Status     *int     `json:"status,omitempty"`
	DurationMS int      `json:"duration_ms"`
	Error      string   `json:"error,omitempty"`
	Response   Response `json:"response"`
}

// ErrDenied is a target refusing the flow with its message.
func ErrDenied(message string) error {
	e := errx.Forbidden(message)
	e.Code = "ACTION_DENIED"
	return e
}

// ErrFailed is an interrupting target failing.
func ErrFailed() error {
	e := errx.External("an action failed")
	e.Code = "ACTION_FAILED"
	return e
}

// ErrUnknownCondition refuses a condition IAMKit does not have.
func ErrUnknownCondition() error {
	e := errx.NotFound("unknown action condition")
	e.Code = "UNKNOWN_CONDITION"
	return e
}

// ValidEndpoint accepts https URLs (http only on loopback, for local
// development) without credentials or fragments.
func ValidEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || len(raw) > 2048 {
		return errx.Validation("url must be an https URL")
	}
	host := u.Hostname()
	if u.Scheme == "https" || (u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1")) {
		return nil
	}
	return errx.Validation("url must be an https URL")
}

func validName(name string) error {
	if n := len([]rune(name)); n == 0 || n > 100 {
		return errx.Validation("name must be 1 to 100 characters")
	}
	return nil
}

func validKind(kind string) error {
	switch kind {
	case KindCall, KindWebhook, KindAsync:
		return nil
	}
	return errx.Validation("kind must be call, webhook or async")
}

func validTimeout(ms int) error {
	if ms < 100 || ms > int(config.ActionMaxTimeout/time.Millisecond) {
		return errx.Validation("timeout_ms must be 100 to 10000")
	}
	return nil
}
