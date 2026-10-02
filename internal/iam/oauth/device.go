package oauth

import (
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Grant types a client may use at the token endpoint
// (oauth_clients.grant_types).
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	// GrantDeviceCode is the OAuth 2.0 Device Authorization Grant (RFC
	// 8628). It needs hosted login: the user approves on /hosted/device.
	GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	// GrantJWTBearer is the RFC 7523 JWT-bearer authorization grant:
	// machine users sign an assertion with one of their keys (no client).
	GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// DefaultGrantTypes are what a client may use when none are given, and
// what every client could use before grant types existed.
var DefaultGrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}

// ValidateGrantTypes checks a client's grant types: known values, no
// duplicates, and at least one grant that yields a token (refresh_token
// alone has nothing to refresh). The device grant needs hosted login.
func ValidateGrantTypes(values []string, hostedLogin bool) error {
	if len(values) == 0 {
		return errx.Validation("grant_types must not be empty")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if v != GrantAuthorizationCode && v != GrantRefreshToken && v != GrantDeviceCode && v != GrantTokenExchange {
			return errx.Validation("grant_types may contain authorization_code, refresh_token, " + GrantDeviceCode + " and " + GrantTokenExchange)
		}
		if seen[v] {
			return errx.Validation("grant_types must not repeat a value")
		}
		seen[v] = true
	}
	if !seen[GrantAuthorizationCode] && !seen[GrantDeviceCode] && !seen[GrantTokenExchange] {
		return errx.Validation("grant_types needs authorization_code, " + GrantDeviceCode + " or " + GrantTokenExchange)
	}
	if seen[GrantDeviceCode] && !hostedLogin {
		return errx.Validation("the device grant requires hosted_login")
	}
	return nil
}

// Allows reports whether the client may use grant at the token endpoint.
func (c *Client) Allows(grant string) bool { return slices.Contains(c.GrantTypes, grant) }

// Device authorization settings (RFC 8628).
const (
	// DeviceCodeTTL is how long the user has to approve a device.
	DeviceCodeTTL = 10 * time.Minute
	// DeviceInterval is the polling interval a device starts with; each
	// slow_down adds DeviceSlowDown.
	DeviceInterval = 5 * time.Second
	DeviceSlowDown = 5 * time.Second
	// UserCodeAlphabet has no vowels (no words) and no easily confused
	// letters; 8 characters give 20^8 ≈ 2.6·10¹⁰ codes.
	UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	UserCodeLength   = 8
	// DeviceVerificationPath is where the user enters the code.
	DeviceVerificationPath = "/hosted/device"
)

// DeviceScopes are the scopes a device may ask for.
var DeviceScopes = []string{"openid", "profile", "email", "phone", "offline_access"}

// ValidateDeviceScope checks a space-separated scope request.
func ValidateDeviceScope(scope string) error {
	for _, s := range strings.Fields(scope) {
		if !slices.Contains(DeviceScopes, s) {
			return errx.Validation("scope may contain openid, profile, email, phone and offline_access")
		}
	}
	return nil
}

// NormalizeUserCode is the canonical form of a typed user code: upper case
// without separators or spaces ("" when it cannot be a user code).
func NormalizeUserCode(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(raw) {
		if r == '-' || r == ' ' {
			continue
		}
		if !strings.ContainsRune(UserCodeAlphabet, r) {
			return ""
		}
		b.WriteRune(r)
	}
	if b.Len() != UserCodeLength {
		return ""
	}
	return b.String()
}

// FormatUserCode shows a normalized user code as XXXX-XXXX.
func FormatUserCode(code string) string {
	if len(code) != UserCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// DeviceAuthorization is the answer of /oauth/device_authorization.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Device statuses (oauth_device_codes.status).
const (
	DevicePending  = "pending"
	DeviceApproved = "approved"
	DeviceDenied   = "denied"
	DeviceConsumed = "consumed"
)

// Device is a stored device authorization.
type Device struct {
	Hash         []byte                  `db:"device_hash"`
	Client       identity.ClientID       `db:"client_id"`
	Environment  identity.EnvironmentID  `db:"environment_id"`
	Scope        string                  `db:"scope"`
	Status       string                  `db:"status"`
	Interval     int                     `db:"interval_seconds"`
	LastPoll     *time.Time              `db:"last_poll_at"`
	Session      identity.SessionID      `db:"session_id"`
	User         identity.UserID         `db:"user_id"`
	Organization identity.OrganizationID `db:"organization_id"`
	Expires      time.Time               `db:"expires_at"`
	Created      time.Time               `db:"created_at"`
	// ApplicationName is shown on the confirmation page.
	ApplicationName string `db:"application_name"`
}

// Poll is the answer to one token request for the device at now, and the
// device as it must be saved: pending devices record the poll (and slow
// down when polled faster than their interval), approved ones become
// consumed. A nil error means the device is redeemed.
func (d Device) Poll(now time.Time) (Device, error) {
	next := d
	if !now.Before(d.Expires) {
		return next, DeviceError(DeviceExpiredToken)
	}
	switch d.Status {
	case DeviceDenied:
		return next, DeviceError(DeviceAccessDenied)
	case DeviceConsumed:
		return next, DeviceError(DeviceInvalidGrant)
	case DeviceApproved:
		next.Status = DeviceConsumed
		return next, nil
	}
	polled := now
	next.LastPoll = &polled
	if d.LastPoll != nil && now.Sub(*d.LastPoll) < time.Duration(d.Interval)*time.Second {
		next.Interval = d.Interval + int(DeviceSlowDown/time.Second)
		return next, DeviceError(DeviceSlowDownError)
	}
	return next, DeviceError(DeviceAuthorizationPending)
}

// Token endpoint errors of the device grant (RFC 8628 §3.5); they are the
// errx Code, which the HTTP adapter sends as the OAuth error.
const (
	DeviceAuthorizationPending = "authorization_pending"
	DeviceSlowDownError        = "slow_down"
	DeviceExpiredToken         = "expired_token"
	DeviceAccessDenied         = "access_denied"
	DeviceInvalidGrant         = "invalid_grant"
)

// DeviceError is a device grant token error.
func DeviceError(code string) *errx.Error {
	e := errx.Validation("device authorization: " + code)
	e.Code = code
	return e
}

// DeviceGrant is a redeemed device authorization: the session the user
// approved it with and the scopes the device asked for.
type DeviceGrant struct {
	Login   Login
	Scopes  []string
	Session SessionInfo
	// Requested is when the device asked for authorization.
	Requested time.Time
}

// DeviceRequest is a pending device authorization shown to the user who
// typed its code: which application asks and for what.
type DeviceRequest struct {
	Client      identity.ClientID
	Environment identity.EnvironmentID
	Application string
	Scopes      []string
}
