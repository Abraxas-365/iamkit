// Package usage meters environments and enforces their limits: totals of
// users, organizations and applications, daily emails and SMS, and
// per-minute API requests and action calls. Deployment caps
// (IAMKIT_LIMITS) are ceilings; an environment's own limits can only
// tighten them.
package usage

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Limit names (environment_limits columns, IAMKIT_LIMITS keys).
const (
	LimitUsers         = "users_max"
	LimitOrganizations = "organizations_max"
	LimitApplications  = "applications_max"
	LimitRequests      = "requests_per_minute"
	LimitEmails        = "emails_per_day"
	LimitSMS           = "sms_per_day"
	LimitActionCalls   = "action_calls_per_minute"
)

// Metric names (usage_daily.metric).
const (
	MetricLogins       = "logins"
	MetricUsersCreated = "users_created"
	MetricTokens       = "tokens"
	MetricEmails       = "emails"
	MetricSMS          = "sms"
	MetricActionCalls  = "action_calls"
	MetricRequests     = "api_requests"
)

// Metrics lists every metric, in display order.
var Metrics = []string{MetricLogins, MetricUsersCreated, MetricTokens, MetricEmails, MetricSMS, MetricActionCalls, MetricRequests}

// Kind says what a limit bounds.
type Kind string

const (
	// KindTotal bounds rows that exist (users, organizations, applications).
	KindTotal Kind = "total"
	// KindDaily bounds a metric per UTC day.
	KindDaily Kind = "daily"
	// KindPerMinute bounds events per minute (fixed window).
	KindPerMinute Kind = "per_minute"
)

// Limit is one entry of the catalog. Metric is what a daily or per-minute
// limit counts.
type Limit struct {
	Name   string
	Kind   Kind
	Metric string
}

// Catalog lists every limit, in display order.
var Catalog = []Limit{
	{LimitUsers, KindTotal, ""},
	{LimitOrganizations, KindTotal, ""},
	{LimitApplications, KindTotal, ""},
	{LimitRequests, KindPerMinute, MetricRequests},
	{LimitEmails, KindDaily, MetricEmails},
	{LimitSMS, KindDaily, MetricSMS},
	{LimitActionCalls, KindPerMinute, MetricActionCalls},
}

// MaxValue bounds a limit (any larger value is a typo).
const MaxValue = 1_000_000_000_000

// Find returns the catalog entry called name.
func Find(name string) (Limit, bool) {
	i := slices.IndexFunc(Catalog, func(l Limit) bool { return l.Name == name })
	if i < 0 {
		return Limit{}, false
	}
	return Catalog[i], true
}

// Values are limits by name; a missing name is unlimited.
type Values map[string]int64

// Max is the value of name and whether it is limited.
func (v Values) Max(name string) (int64, bool) {
	n, ok := v[name]
	return n, ok
}

// Tighten keeps the smaller of each limit; a limit set on either side
// applies.
func (v Values) Tighten(other Values) Values {
	out := Values{}
	for k, n := range v {
		out[k] = n
	}
	for k, n := range other {
		if current, ok := out[k]; !ok || n < current {
			out[k] = n
		}
	}
	return out
}

// Validate refuses names outside the catalog and negative or huge values.
func (v Values) Validate() error {
	for _, name := range v.names() {
		if _, ok := Find(name); !ok {
			return errx.Validation("unknown limit " + strconv.Quote(name))
		}
		if n := v[name]; n < 0 || n > MaxValue {
			return errx.Validation(name + " must be between 0 and " + strconv.Itoa(MaxValue))
		}
	}
	return nil
}

func (v Values) names() []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseDeployment reads IAMKIT_LIMITS: comma-separated name=value pairs.
func ParseDeployment(raw string) (Values, error) {
	out := Values{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, value, found := strings.Cut(item, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if !found || err != nil {
			return nil, errx.Validation("IAMKIT_LIMITS: " + name + " needs a whole number")
		}
		out[name] = n
	}
	if err := out.Validate(); err != nil {
		return nil, errx.Validation("IAMKIT_LIMITS: " + err.Error())
	}
	return out, nil
}

// Set replaces an environment's limits: a name with a number limits it,
// null or absent leaves it to the deployment.
type Set map[string]*int64

// Values drops the nulls.
func (s Set) Values() Values {
	out := Values{}
	for k, n := range s {
		if n != nil {
			out[k] = *n
		}
	}
	return out
}

// Limits is an environment's view of its limits: the deployment caps, its
// own limits and the effective (tighter) values.
type Limits struct {
	Deployment  Values     `json:"deployment"`
	Environment Values     `json:"environment"`
	Effective   Values     `json:"effective"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// Stored is an environment's saved limits.
type Stored struct {
	Values    Values
	UpdatedAt *time.Time
}

// Mutation is the audit context of a limits change. Owner says whether the
// operator is a workspace owner: only owners change limits.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
	Owner       bool
}

// Increment adds Count to one metric of one environment and UTC day.
type Increment struct {
	Environment identity.EnvironmentID
	Day         time.Time
	Metric      string
	Count       int64
}

// Day is one UTC day of usage; every metric is present.
type Day struct {
	Day     string           `json:"day"`
	Metrics map[string]int64 `json:"metrics"`
}

// Total is a bounded count of what exists now.
type Total struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	Max   *int64 `json:"max"`
}

// Report is an environment's usage over the last days, oldest first, and
// its current totals against their limits.
type Report struct {
	Days   []Day            `json:"days"`
	Totals map[string]int64 `json:"totals"`
	Now    []Total          `json:"now"`
}

// MaxDays bounds a report's range.
const MaxDays = 366

// ErrExceeded is the refusal of a limit: 422 for totals, 429 for rates.
func ErrExceeded(l Limit, max int64) error {
	var e *errx.Error
	switch l.Kind {
	case KindTotal:
		e = errx.Business("the environment reached its " + l.Name + " limit")
	default:
		e = errx.TooManyRequests("the environment reached its " + l.Name + " limit")
	}
	e.Code = "QUOTA_EXCEEDED"
	e.Public = true
	return e.WithDetails(map[string]any{"limit": l.Name, "max": max})
}

// Exceeded reports a QUOTA_EXCEEDED error.
func Exceeded(err error) bool {
	var e *errx.Error
	return errx.As(err, &e) && e.Code == "QUOTA_EXCEEDED"
}

// UTCDay is the UTC day of t.
func UTCDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
