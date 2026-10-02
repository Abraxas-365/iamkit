package iamclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// ActionTarget is an endpoint IAMKit calls when a condition it is bound to
// runs. Kind is "call" (the answer is applied), "webhook" (2xx only) or
// "async" (background, never changes or stops the flow).
type ActionTarget struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	URL              string    `json:"url"`
	Kind             string    `json:"kind"`
	TimeoutMS        int       `json:"timeout_ms"`
	InterruptOnError bool      `json:"interrupt_on_error"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ActionTargetInput creates a target (Name and URL required; Kind defaults
// to "call", TimeoutMS to 5000) or updates one (only non-nil fields).
type ActionTargetInput struct {
	Name             *string `json:"name,omitempty"`
	URL              *string `json:"url,omitempty"`
	Kind             *string `json:"kind,omitempty"`
	TimeoutMS        *int    `json:"timeout_ms,omitempty"`
	InterruptOnError *bool   `json:"interrupt_on_error,omitempty"`
}

// ActionSecret is returned once on create and rotation: verify requests
// with it (see package action).
type ActionSecret struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// ActionCondition is a point where targets can run and what they may
// answer: Deny, Claims, or a Patch of the listed fields.
type ActionCondition struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Deny        bool     `json:"deny"`
	Claims      bool     `json:"claims"`
	Patch       []string `json:"patch,omitempty"`
}

// ActionExecution binds a condition to targets, called in order.
type ActionExecution struct {
	Condition string    `json:"condition"`
	Targets   []string  `json:"targets"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ActionCall is one logged target call (kept 7 days). Outcome is ok,
// denied, failed or skipped (circuit breaker open).
type ActionCall struct {
	ID         int64     `json:"id"`
	TargetID   string    `json:"target_id"`
	Condition  string    `json:"condition"`
	Outcome    string    `json:"outcome"`
	Status     *int      `json:"status,omitempty"`
	DurationMS int       `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ActionCallFilter narrows ActionCalls; zero fields match everything.
type ActionCallFilter struct {
	TargetID  string
	Condition string
	Outcome   string
	Limit     int
}

// ActionTest is a test call's outcome and the target's answer (never
// applied).
type ActionTest struct {
	Outcome    string          `json:"outcome"`
	Status     *int            `json:"status,omitempty"`
	DurationMS int             `json:"duration_ms"`
	Error      string          `json:"error,omitempty"`
	Response   json.RawMessage `json:"response"`
}

var conditionName = regexp.MustCompile(`^[a-z]+:[a-z_.]+$`)

func (e Environment) ActionConditions(ctx context.Context) ([]ActionCondition, error) {
	return list[ActionCondition](e, ctx, "action-conditions")
}

func (e Environment) ActionTargets(ctx context.Context) ([]ActionTarget, error) {
	return list[ActionTarget](e, ctx, "action-targets")
}

func (e Environment) ActionTarget(ctx context.Context, id string) (ActionTarget, error) {
	var out ActionTarget
	err := e.operation(ctx, "GET", []string{"action-targets", id}, nil, &out)
	return out, err
}

func (e Environment) CreateActionTarget(ctx context.Context, input ActionTargetInput) (ActionSecret, error) {
	var out ActionSecret
	err := e.operation(ctx, "POST", []string{"action-targets"}, input, &out)
	return out, err
}

func (e Environment) UpdateActionTarget(ctx context.Context, id string, input ActionTargetInput) (ActionTarget, error) {
	var out ActionTarget
	err := e.operation(ctx, "PATCH", []string{"action-targets", id}, input, &out)
	return out, err
}

// DeleteActionTarget deletes a target and removes it from every condition.
func (e Environment) DeleteActionTarget(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"action-targets", id}, nil, nil)
}

// RotateActionTargetSecret returns a new secret; the previous one keeps
// signing for 24 hours.
func (e Environment) RotateActionTargetSecret(ctx context.Context, id string) (ActionSecret, error) {
	var out ActionSecret
	err := e.operation(ctx, "POST", []string{"action-targets", id, "rotate-secret"}, map[string]any{}, &out)
	return out, err
}

// TestActionTarget calls a target for condition with input (the Input
// JSON a receiver gets; nil sends only the condition and environment) and
// returns the answer without applying it. The call is logged.
func (e Environment) TestActionTarget(ctx context.Context, id, condition string, input json.RawMessage) (ActionTest, error) {
	var out ActionTest
	body := map[string]any{"condition": condition}
	if input != nil {
		body["input"] = input
	}
	err := e.operation(ctx, "POST", []string{"action-targets", id, "test"}, body, &out)
	return out, err
}

func (e Environment) ActionExecutions(ctx context.Context) ([]ActionExecution, error) {
	return list[ActionExecution](e, ctx, "action-executions")
}

// SetActionExecution sets the targets condition calls, in order.
func (e Environment) SetActionExecution(ctx context.Context, condition string, targets []string) (ActionExecution, error) {
	var out ActionExecution
	if !conditionName.MatchString(condition) {
		return out, fmt.Errorf("invalid condition")
	}
	if targets == nil {
		targets = []string{}
	}
	err := e.client.Do(ctx, "PUT", e.path("action-executions/"+url.PathEscape(condition)), map[string]any{"targets": targets}, &out)
	return out, err
}

// DeleteActionExecution stops calling targets for condition.
func (e Environment) DeleteActionExecution(ctx context.Context, condition string) error {
	if !conditionName.MatchString(condition) {
		return fmt.Errorf("invalid condition")
	}
	return e.client.Do(ctx, "DELETE", e.path("action-executions/"+url.PathEscape(condition)), nil, nil)
}

// ActionCalls lists recent target calls, newest first.
func (e Environment) ActionCalls(ctx context.Context, filter ActionCallFilter) ([]ActionCall, error) {
	query := url.Values{}
	for key, value := range map[string]string{"target_id": filter.TargetID, "condition": filter.Condition, "outcome": filter.Outcome} {
		if value != "" {
			query.Set(key, value)
		}
	}
	if filter.Limit > 0 {
		query.Set("limit", strconv.Itoa(filter.Limit))
	}
	var out paginated[ActionCall]
	if err := e.client.do(ctx, "GET", e.path("action-calls"), query, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []ActionCall{}, nil
	}
	return out.Items, nil
}
