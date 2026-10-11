package risk

import (
	"slices"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Attempt outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	// OutcomeBlocked: a deny restriction or a block detection refused it.
	OutcomeBlocked = "blocked"
	// OutcomeChallenged: the sign-in must answer an emailed code first.
	OutcomeChallenged = "challenged"
	// OutcomeCaptchaFailed: the CAPTCHA was missing or invalid.
	OutcomeCaptchaFailed = "captcha_failed"
)

// Outcomes lists the outcomes, in display order.
var Outcomes = []string{OutcomeSuccess, OutcomeFailure, OutcomeBlocked, OutcomeChallenged, OutcomeCaptchaFailed}

// Reasons of a blocked attempt (Attempt.Reason).
const (
	ReasonRestriction = "restriction"
	ReasonDetection   = "detection"
)

// Attempt is one recorded sign-in attempt. User is set when the account
// was identified (a wrong password on a known account included); unknown
// logins are only counted through their HMAC, never stored.
type Attempt struct {
	ID           identity.SignInAttemptID `json:"id"`
	Environment  identity.EnvironmentID   `json:"environment_id"`
	User         *identity.UserID         `json:"user_id,omitempty"`
	Organization *identity.OrganizationID `json:"organization_id,omitempty"`
	IP           string                   `json:"ip,omitempty"`
	UserAgent    string                   `json:"user_agent,omitempty"`
	Country      string                   `json:"country,omitempty"`
	Latitude     *float64                 `json:"latitude,omitempty"`
	Longitude    *float64                 `json:"longitude,omitempty"`
	// Device says a device id came with the attempt (the id is never
	// returned).
	Device     bool      `json:"device"`
	Method     string    `json:"method"`
	Surface    string    `json:"surface"`
	Outcome    string    `json:"outcome"`
	Reason     string    `json:"reason,omitempty"`
	Detections []string  `json:"detections"`
	Action     string    `json:"action"`
	Captcha    string    `json:"captcha,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// AttemptFilter narrows the attempt log. Before is a keyset cursor (an
// attempt id; newest first below it).
type AttemptFilter struct {
	User      *identity.UserID
	IP        string
	Outcome   string
	Detection string
	Country   string
	Before    *identity.SignInAttemptID
	Limit     int
}

// Validate checks the filter.
func (f AttemptFilter) Validate() error {
	if f.Outcome != "" && !slices.Contains(Outcomes, f.Outcome) {
		return errx.Validation("unknown outcome")
	}
	if f.Detection != "" && !slices.Contains(Detections, f.Detection) {
		return errx.Validation("unknown detection")
	}
	if f.Country != "" && !countryCode.MatchString(f.Country) {
		return errx.Validation("country must be an ISO 3166-1 alpha-2 code")
	}
	return nil
}

// AttemptPage is one page of the attempt log, newest first; Next is the
// Before cursor of the next page (zero = no more).
type AttemptPage struct {
	Items []Attempt                 `json:"items"`
	Next  *identity.SignInAttemptID `json:"next,omitempty"`
}

// MaxAttemptPage caps an attempt page; DefaultAttemptPage is the default.
const (
	MaxAttemptPage     = 200
	DefaultAttemptPage = 50
)

// AttemptLimit clamps a requested page size.
func AttemptLimit(n int) int {
	if n <= 0 {
		return DefaultAttemptPage
	}
	return min(n, MaxAttemptPage)
}

// Device is a device a user signed in from.
type Device struct {
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	LastIP      string    `json:"last_ip,omitempty"`
	LastCountry string    `json:"last_country,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
}

// Counts are the recent failures detections read.
type Counts struct {
	UserFailures1h     int `json:"user_failures_1h"`
	IPFailures1h       int `json:"ip_failures_1h"`
	IPDistinctLogins1h int `json:"-"`
}

// Last is a user's previous successful sign-in with a location (impossible
// travel).
type Last struct {
	At        time.Time
	Latitude  float64
	Longitude float64
	Country   string
}
