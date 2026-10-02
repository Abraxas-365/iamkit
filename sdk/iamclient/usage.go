package iamclient

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// Limit names (IAMKIT_LIMITS keys). Totals bound what exists (422
// QUOTA_EXCEEDED), daily limits a UTC day and per-minute limits a minute
// (429 QUOTA_EXCEEDED).
const (
	LimitUsers         = "users_max"
	LimitOrganizations = "organizations_max"
	LimitApplications  = "applications_max"
	LimitRequests      = "requests_per_minute"
	LimitEmails        = "emails_per_day"
	LimitSMS           = "sms_per_day"
	LimitActionCalls   = "action_calls_per_minute"
)

// Limits are an environment's limits by name; a missing name is
// unlimited. Deployment holds IAMKIT_LIMITS, Environment the environment's
// own limits and Effective the tighter of both.
type Limits struct {
	Deployment  map[string]int64 `json:"deployment"`
	Environment map[string]int64 `json:"environment"`
	Effective   map[string]int64 `json:"effective"`
	UpdatedAt   *time.Time       `json:"updated_at,omitempty"`
}

// UsageDay is one UTC day (YYYY-MM-DD) of usage; every metric is present.
type UsageDay struct {
	Day     string           `json:"day"`
	Metrics map[string]int64 `json:"metrics"`
}

// UsageTotal is what exists now against its limit (Max nil = unlimited).
type UsageTotal struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Max   *int64 `json:"max"`
}

// Usage is an environment's usage over the last days, oldest first. Metrics:
// logins, users_created, tokens, emails, sms, action_calls, api_requests.
type Usage struct {
	Days   []UsageDay       `json:"days"`
	Totals map[string]int64 `json:"totals"`
	Now    []UsageTotal     `json:"now"`
}

// Limits returns the environment's limits.
func (e Environment) Limits(ctx context.Context) (Limits, error) {
	var out Limits
	err := e.operation(ctx, "GET", []string{"limits"}, nil, &out)
	return out, err
}

// SetLimits replaces the environment's limits: a name with a number limits
// it, a missing name leaves it to the deployment. Limits above the
// deployment's caps do not loosen them. Workspace owners only; audited as
// limits.updated.
func (e Environment) SetLimits(ctx context.Context, limits map[string]int64) (Limits, error) {
	if limits == nil {
		limits = map[string]int64{}
	}
	var out Limits
	err := e.operation(ctx, "PUT", []string{"limits"}, limits, &out)
	return out, err
}

// Usage returns the usage of the last days (1 to 366, today included; 0
// asks for the server's default of 30).
func (e Environment) Usage(ctx context.Context, days int) (Usage, error) {
	var query url.Values
	if days != 0 {
		query = url.Values{"days": {strconv.Itoa(days)}}
	}
	var out Usage
	err := e.client.do(ctx, "GET", e.path("usage"), query, nil, &out)
	return out, err
}
