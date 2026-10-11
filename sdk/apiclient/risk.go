package apiclient

import (
	"context"

	"github.com/Abraxas-365/iamkit/sdk/iamclient"
)

// Bot protection and risk signals share iamclient's types.
type (
	CaptchaConfig         = iamclient.CaptchaConfig
	CaptchaInput          = iamclient.CaptchaInput
	PublicCaptcha         = iamclient.PublicCaptcha
	RiskThresholds        = iamclient.RiskThresholds
	RiskPolicy            = iamclient.RiskPolicy
	RiskPolicyInput       = iamclient.RiskPolicyInput
	RiskRestriction       = iamclient.RiskRestriction
	NewRiskRestriction    = iamclient.NewRiskRestriction
	RiskRestrictionFilter = iamclient.RiskRestrictionFilter
	SignInAttempt         = iamclient.SignInAttempt
	SignInAttemptFilter   = iamclient.SignInAttemptFilter
	SignInAttemptPage     = iamclient.SignInAttemptPage
	UserDevice            = iamclient.UserDevice
	GeoIPStatus           = iamclient.GeoIPStatus
	RiskStatus            = iamclient.RiskStatus
)

// Constants of the security routes.
const (
	CaptchaTurnstile       = iamclient.CaptchaTurnstile
	CaptchaHCaptcha        = iamclient.CaptchaHCaptcha
	RiskIPVelocity         = iamclient.RiskIPVelocity
	RiskUserBruteForce     = iamclient.RiskUserBruteForce
	RiskImpossibleTravel   = iamclient.RiskImpossibleTravel
	RiskNewDevice          = iamclient.RiskNewDevice
	RiskStaleAccount       = iamclient.RiskStaleAccount
	RiskActionOff          = iamclient.RiskActionOff
	RiskActionLog          = iamclient.RiskActionLog
	RiskActionNotify       = iamclient.RiskActionNotify
	RiskActionChallenge    = iamclient.RiskActionChallenge
	RiskActionBlock        = iamclient.RiskActionBlock
	RestrictionIP          = iamclient.RestrictionIP
	RestrictionCountry     = iamclient.RestrictionCountry
	RestrictionEmailDomain = iamclient.RestrictionEmailDomain
	RestrictionAllow       = iamclient.RestrictionAllow
	RestrictionDeny        = iamclient.RestrictionDeny
	AttemptSuccess         = iamclient.AttemptSuccess
	AttemptFailure         = iamclient.AttemptFailure
	AttemptBlocked         = iamclient.AttemptBlocked
	AttemptChallenged      = iamclient.AttemptChallenged
	AttemptCaptchaFailed   = iamclient.AttemptCaptchaFailed
)

// Captcha reads the CAPTCHA configuration (404 without one); requires iam:security:read.
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
	err := e.client.Do(ctx, "GET", e.path("users", user, "devices"), nil, &out)
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
