package authclient

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// DeviceGrantType is the RFC 8628 grant type (oauth client grant_types).
const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DeviceAuthorization is the answer of /oauth/device_authorization: show
// UserCode and VerificationURI (or VerificationURIComplete, e.g. as a QR
// code) to the user, then poll with DeviceCode every Interval seconds.
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Device grant polling errors (OAuthError.Code).
const (
	DeviceAuthorizationPending = "authorization_pending"
	DeviceSlowDown             = "slow_down"
	DeviceExpired              = "expired_token"
	DeviceAccessDenied         = "access_denied"
)

// AuthorizeDevice starts a device authorization (RFC 8628) for a client
// whose grant_types include DeviceGrantType. scopes may be empty.
func (c *OAuthClient) AuthorizeDevice(ctx context.Context, scopes ...string) (DeviceAuthorization, error) {
	var out DeviceAuthorization
	form := url.Values{}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	err := c.request(ctx, "device_authorization", form, &out)
	return out, err
}

// PollDevice asks once for the tokens of a device authorization. Until the
// user decides it fails with an *OAuthError whose Code is
// DeviceAuthorizationPending or DeviceSlowDown.
func (c *OAuthClient) PollDevice(ctx context.Context, deviceCode string) (OAuthTokens, error) {
	var out OAuthTokens
	err := c.request(ctx, "token", url.Values{"grant_type": {DeviceGrantType}, "device_code": {deviceCode}}, &out)
	return out, err
}

// deviceStep is the unit of the polling interval (shortened in tests).
var deviceStep = time.Second

// WaitDevice polls at the authorization's interval (five seconds more
// after each slow_down) until the user approves (tokens), denies
// (DeviceAccessDenied), the code expires (DeviceExpired) or ctx ends.
func (c *OAuthClient) WaitDevice(ctx context.Context, authorization DeviceAuthorization) (OAuthTokens, error) {
	interval := time.Duration(authorization.Interval) * deviceStep
	if interval <= 0 {
		interval = 5 * deviceStep
	}
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return OAuthTokens{}, ctx.Err()
		case <-timer.C:
		}
		tokens, err := c.PollDevice(ctx, authorization.DeviceCode)
		var failure *OAuthError
		if !errors.As(err, &failure) {
			return tokens, err
		}
		switch failure.Code {
		case DeviceAuthorizationPending:
		case DeviceSlowDown:
			interval += 5 * deviceStep
		default:
			return tokens, err
		}
	}
}
