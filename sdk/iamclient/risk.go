package iamclient

import (
	"context"
	"net/url"
	"strconv"
	"time"
)

// CAPTCHA providers.
const (
	CaptchaTurnstile = "turnstile"
	CaptchaHCaptcha  = "hcaptcha"
)

// Risk detections, their actions, restriction kinds and attempt outcomes.
const (
	RiskIPVelocity       = "ip_velocity"
	RiskUserBruteForce   = "user_brute_force"
	RiskImpossibleTravel = "impossible_travel"
	RiskNewDevice        = "new_device"
	RiskStaleAccount     = "stale_account"

	RiskActionOff       = "off"
	RiskActionLog       = "log"
	RiskActionNotify    = "notify"
	RiskActionChallenge = "challenge"
	RiskActionBlock     = "block"

	RestrictionIP          = "ip"
	RestrictionCountry     = "country"
	RestrictionEmailDomain = "email_domain"
	RestrictionAllow       = "allow"
	RestrictionDeny        = "deny"

	AttemptSuccess       = "success"
	AttemptFailure       = "failure"
	AttemptBlocked       = "blocked"
	AttemptChallenged    = "challenged"
	AttemptCaptchaFailed = "captcha_failed"
)

// CaptchaConfig is the environment's CAPTCHA (Cloudflare Turnstile or
// hCaptcha). The secret is write-only; HasSecret says one is stored.
type CaptchaConfig struct {
	EnvironmentID string `json:"environment_id"`
	// Provider is "turnstile" or "hcaptcha".
	Provider  string `json:"provider"`
	SiteKey   string `json:"site_key"`
	HasSecret bool   `json:"has_secret"`
	// Hosted and Headless switch the check on the hosted pages and on the
	// headless routes (/login, /challenges, /signup, LDAP login).
	Hosted   bool `json:"hosted"`
	Headless bool `json:"headless"`
	// Hostnames are extra host names a headless token may be solved on.
	Hostnames []string  `json:"hostnames"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CaptchaInput replaces the CAPTCHA configuration (SaveCaptcha). Secret nil
// keeps the stored one (required the first time); Hosted/Headless nil
// default to on.
type CaptchaInput struct {
	Provider  string   `json:"provider"`
	SiteKey   string   `json:"site_key"`
	Secret    *string  `json:"secret,omitempty"`
	Hosted    *bool    `json:"hosted,omitempty"`
	Headless  *bool    `json:"headless,omitempty"`
	Hostnames []string `json:"hostnames,omitempty"`
}

// PublicCaptcha is what a sign-in UI needs to render the widget (the
// public GET /identity/v1/captcha/<environment>): Enabled is false when
// headless sign-in needs no CAPTCHA.
type PublicCaptcha struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
	SiteKey  string `json:"site_key,omitempty"`
	Headless bool   `json:"headless,omitempty"`
}

// RiskThresholds tune the detections; 0 on input keeps the default.
type RiskThresholds struct {
	IPFailuresPerHour       int `json:"ip_failures_per_hour"`
	IPDistinctLoginsPerHour int `json:"ip_distinct_logins_per_hour"`
	UserFailuresPerHour     int `json:"user_failures_per_hour"`
	StaleAfterDays          int `json:"stale_after_days"`
	TravelSpeedKmh          int `json:"travel_speed_kmh"`
}

// RiskPolicy is the environment's risk policy: Actions maps each detection
// (ip_velocity, user_brute_force, impossible_travel, new_device,
// stale_account) to off, log, notify, challenge or block. Saved is false
// for the default policy (every detection off).
type RiskPolicy struct {
	EnvironmentID       string            `json:"environment_id"`
	Actions             map[string]string `json:"actions"`
	Thresholds          RiskThresholds    `json:"thresholds"`
	NotifyUser          bool              `json:"notify_user"`
	BlockIfUnverifiable bool              `json:"block_if_unverifiable"`
	Saved               bool              `json:"saved"`
	UpdatedAt           *time.Time        `json:"updated_at,omitempty"`
}

// RiskPolicyInput replaces the policy (SaveRiskPolicy). Omitted detections
// are off; a nil Thresholds or NotifyUser keeps the defaults.
type RiskPolicyInput struct {
	Actions             map[string]string `json:"actions"`
	Thresholds          *RiskThresholds   `json:"thresholds,omitempty"`
	NotifyUser          *bool             `json:"notify_user,omitempty"`
	BlockIfUnverifiable bool              `json:"block_if_unverifiable"`
}

// RiskRestriction is an allow/deny rule: Kind ip (address or CIDR),
// country (ISO 3166-1 alpha-2) or email_domain; Action allow or deny.
type RiskRestriction struct {
	ID            string    `json:"id"`
	EnvironmentID string    `json:"environment_id"`
	Kind          string    `json:"kind"`
	Value         string    `json:"value"`
	Action        string    `json:"action"`
	Note          string    `json:"note"`
	CreatedAt     time.Time `json:"created_at"`
}

// NewRiskRestriction adds a restriction.
type NewRiskRestriction struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Action string `json:"action"`
	Note   string `json:"note,omitempty"`
}

// RiskRestrictionFilter narrows RiskRestrictions; empty fields do not filter.
type RiskRestrictionFilter struct {
	Kind   string
	Action string
}

// Query encodes the filter as query parameters.
func (f RiskRestrictionFilter) Query() url.Values {
	q := url.Values{}
	if f.Kind != "" {
		q.Set("kind", f.Kind)
	}
	if f.Action != "" {
		q.Set("action", f.Action)
	}
	return q
}

// SignInAttempt is one entry of the sign-in attempt log. The login typed is
// never stored; Device says a device id was sent.
type SignInAttempt struct {
	ID             string   `json:"id"`
	EnvironmentID  string   `json:"environment_id"`
	UserID         string   `json:"user_id,omitempty"`
	OrganizationID string   `json:"organization_id,omitempty"`
	IP             string   `json:"ip,omitempty"`
	UserAgent      string   `json:"user_agent,omitempty"`
	Country        string   `json:"country,omitempty"`
	Latitude       *float64 `json:"latitude,omitempty"`
	Longitude      *float64 `json:"longitude,omitempty"`
	Device         bool     `json:"device"`
	Method         string   `json:"method"`
	// Surface is "hosted" or "headless".
	Surface string `json:"surface"`
	// Outcome is success, failure, blocked, challenged or captcha_failed.
	Outcome    string   `json:"outcome"`
	Reason     string   `json:"reason,omitempty"`
	Detections []string `json:"detections"`
	// Action is the strongest action taken: none, log, notify, challenge or
	// block.
	Action string `json:"action"`
	// Captcha is "", "passed", "failed" or "unavailable".
	Captcha   string    `json:"captcha,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// SignInAttemptFilter narrows SignInAttempts; empty fields do not filter.
// Attempts come newest first: pass the previous page's Next as Before.
type SignInAttemptFilter struct {
	UserID    string
	IP        string
	Outcome   string
	Detection string
	Country   string
	// Before is the cursor (an attempt ID) of the next page.
	Before string
	// Limit is the page size (default 50, at most 200).
	Limit int
}

// Query encodes the filter as query parameters.
func (f SignInAttemptFilter) Query() url.Values {
	q := url.Values{}
	for key, value := range map[string]string{
		"user_id":   f.UserID,
		"ip":        f.IP,
		"outcome":   f.Outcome,
		"detection": f.Detection,
		"country":   f.Country,
		"before":    f.Before,
	} {
		if value != "" {
			q.Set(key, value)
		}
	}
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	return q
}

// SignInAttemptPage is one page of attempts; Next is the Before of the next
// page ("" = no more).
type SignInAttemptPage struct {
	Items []SignInAttempt `json:"items"`
	Next  string          `json:"next,omitempty"`
}

// UserDevice is a device a user signed in from (never its id).
type UserDevice struct {
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	LastIP      string    `json:"last_ip,omitempty"`
	LastCountry string    `json:"last_country,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
}

// GeoIPStatus describes the deployment's GeoIP.
type GeoIPStatus struct {
	// Source is "none", "mmdb" (IAMKIT_GEOIP_DB) or "header"
	// (IAMKIT_GEOIP_HEADER).
	Source    string     `json:"source"`
	Database  string     `json:"database,omitempty"`
	Header    string     `json:"header,omitempty"`
	BuildDate *time.Time `json:"build_date,omitempty"`
	// Countries: country rules work; Travel: impossible travel works.
	Countries bool   `json:"countries"`
	Travel    bool   `json:"travel"`
	Error     string `json:"error,omitempty"`
}

// RiskStatus says what the deployment supports for the environment.
type RiskStatus struct {
	GeoIP       GeoIPStatus `json:"geoip"`
	Captcha     bool        `json:"captcha"`
	RiskSignals bool        `json:"risk_signals"`
}

// Captcha reads the CAPTCHA configuration (404 without one); requires
// iam:security:read on /api/v1.
func (e Environment) Captcha(ctx context.Context) (CaptchaConfig, error) {
	var out CaptchaConfig
	err := e.operation(ctx, "GET", []string{"captcha"}, nil, &out)
	return out, err
}

// SaveCaptcha creates or replaces the CAPTCHA configuration. The secret is
// sealed (422 ENCRYPTION_KEY_REQUIRED without an encryption key) and
// checked with the provider. Audited as captcha.update.
func (e Environment) SaveCaptcha(ctx context.Context, input CaptchaInput) (CaptchaConfig, error) {
	var out CaptchaConfig
	err := e.operation(ctx, "PUT", []string{"captcha"}, input, &out)
	return out, err
}

// DeleteCaptcha removes the CAPTCHA configuration (sign-in no longer asks
// for it). Audited as captcha.delete.
func (e Environment) DeleteCaptcha(ctx context.Context) error {
	return e.operation(ctx, "DELETE", []string{"captcha"}, nil, nil)
}

// TestCaptcha checks the stored secret with the provider (nil = accepted;
// at most five a minute).
func (e Environment) TestCaptcha(ctx context.Context) error {
	return e.operation(ctx, "POST", []string{"captcha", "test"}, nil, nil)
}

// RiskPolicy reads the risk policy; the default (Saved false, every
// detection off) when none was saved.
func (e Environment) RiskPolicy(ctx context.Context) (RiskPolicy, error) {
	var out RiskPolicy
	err := e.operation(ctx, "GET", []string{"risk-policy"}, nil, &out)
	return out, err
}

// SaveRiskPolicy replaces the risk policy. Audited as risk_policy.update.
func (e Environment) SaveRiskPolicy(ctx context.Context, input RiskPolicyInput) (RiskPolicy, error) {
	var out RiskPolicy
	err := e.operation(ctx, "PUT", []string{"risk-policy"}, input, &out)
	return out, err
}

// DeleteRiskPolicy returns to the default policy (every detection off).
func (e Environment) DeleteRiskPolicy(ctx context.Context) error {
	return e.operation(ctx, "DELETE", []string{"risk-policy"}, nil, nil)
}

// RiskRestrictions lists the allow/deny rules.
func (e Environment) RiskRestrictions(ctx context.Context, filter RiskRestrictionFilter) ([]RiskRestriction, error) {
	var out struct {
		Items []RiskRestriction `json:"items"`
	}
	err := e.client.do(ctx, "GET", e.path("risk-restrictions"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []RiskRestriction{}
	}
	return out.Items, err
}

// CreateRiskRestriction adds a rule (409 for a duplicate kind and value,
// 422 RESTRICTION_LIMIT_REACHED past 1000). Audited as
// risk_restriction.create.
func (e Environment) CreateRiskRestriction(ctx context.Context, input NewRiskRestriction) (RiskRestriction, error) {
	var out RiskRestriction
	err := e.operation(ctx, "POST", []string{"risk-restrictions"}, input, &out)
	return out, err
}

// DeleteRiskRestriction removes a rule. Audited as risk_restriction.delete.
func (e Environment) DeleteRiskRestriction(ctx context.Context, id string) error {
	return e.operation(ctx, "DELETE", []string{"risk-restrictions", id}, nil, nil)
}

// SignInAttempts reads one page of the sign-in attempt log, newest first.
func (e Environment) SignInAttempts(ctx context.Context, filter SignInAttemptFilter) (SignInAttemptPage, error) {
	var out SignInAttemptPage
	err := e.client.do(ctx, "GET", e.path("sign-in-attempts"), filter.Query(), nil, &out)
	if out.Items == nil {
		out.Items = []SignInAttempt{}
	}
	return out, err
}

// SignInAttempt reads one attempt.
func (e Environment) SignInAttempt(ctx context.Context, id string) (SignInAttempt, error) {
	var out SignInAttempt
	err := e.operation(ctx, "GET", []string{"sign-in-attempts", id}, nil, &out)
	return out, err
}

// UserDevices lists the devices a user signed in from, newest first.
func (e Environment) UserDevices(ctx context.Context, user string) ([]UserDevice, error) {
	var out struct {
		Items []UserDevice `json:"items"`
	}
	if err := safeSegment(user); err != nil {
		return nil, err
	}
	err := e.client.Do(ctx, "GET", e.path("users/"+user+"/devices"), nil, &out)
	if out.Items == nil {
		out.Items = []UserDevice{}
	}
	return out.Items, err
}

// RiskStatus reports the deployment's GeoIP and whether CAPTCHA and risk
// signals are enabled for the environment.
func (e Environment) RiskStatus(ctx context.Context) (RiskStatus, error) {
	var out RiskStatus
	err := e.operation(ctx, "GET", []string{"risk", "status"}, nil, &out)
	return out, err
}
