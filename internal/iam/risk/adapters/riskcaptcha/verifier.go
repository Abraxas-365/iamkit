// Package riskcaptcha calls the siteverify endpoints of Cloudflare
// Turnstile and hCaptcha. Requests dial public addresses only; tests
// replace the transport (bootstrap.WithCaptchaTransport).
package riskcaptcha

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/Abraxas-365/iamkit/internal/telemetry"
)

// Endpoints are the providers' siteverify URLs.
var Endpoints = map[string]string{
	risk.ProviderTurnstile: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	risk.ProviderHCaptcha:  "https://api.hcaptcha.com/siteverify",
}

// maxAnswer caps the body read from a provider.
const maxAnswer = 64 << 10

// Guarded is the shared transport: public addresses only.
var Guarded = sync.OnceValue(func() http.RoundTripper {
	return &http.Transport{
		DialContext:           netx.GuardedDialer().DialContext,
		TLSHandshakeTimeout:   config.ExternalHTTPTimeout,
		ResponseHeaderTimeout: config.CaptchaTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
		ForceAttemptHTTP2:     true,
	}
})

// Verifier implements risk.Verifier.
type Verifier struct {
	// Transport replaces Guarded (tests).
	Transport http.RoundTripper
	// Timeout bounds a call (default config.CaptchaTimeout).
	Timeout time.Duration
}

var _ risk.Verifier = Verifier{}

type answer struct {
	Success    bool     `json:"success"`
	Hostname   string   `json:"hostname"`
	Action     string   `json:"action"`
	ErrorCodes []string `json:"error-codes"`
}

// testingSecrets are the providers' published testing secrets: they accept
// any token and answer a placeholder hostname, so the hostname is not
// checked (the operator configured a CAPTCHA that lets everyone through).
var testingSecrets = map[string]bool{
	"1x0000000000000000000000000000000AA":        true, // Turnstile: always passes
	"2x0000000000000000000000000000000AA":        true, // Turnstile: always fails
	"3x0000000000000000000000000000000AA":        true, // Turnstile: token already spent
	"0x0000000000000000000000000000000000000000": true, // hCaptcha
}

// Verify posts the secret, the response and the client address (form
// encoded) to the provider. An error means the provider gave no usable
// answer: transport failure, timeout, 5xx or an unreadable body. A
// provider saying "invalid" is an Answer with Success false.
func (v Verifier) Verify(ctx context.Context, provider, secret string, check risk.CaptchaCheck) (risk.Answer, error) {
	endpoint, ok := Endpoints[provider]
	if !ok {
		return risk.Answer{}, errx.Validation("unknown CAPTCHA provider")
	}
	form := url.Values{"secret": {secret}, "response": {check.Token}}
	if check.RemoteIP != "" {
		form.Set("remoteip", check.RemoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return risk.Answer{}, errx.Wrap(err, "prepare CAPTCHA verification", errx.TypeInternal)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IAMKit")
	transport := v.Transport
	if transport == nil {
		transport = Guarded()
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = config.CaptchaTimeout
	}
	client := http.Client{Transport: telemetry.Transport(transport), Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return risk.Answer{}, errx.External("CAPTCHA provider unreachable: " + netx.Reason(err))
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer))
	if err != nil {
		return risk.Answer{}, errx.External("CAPTCHA provider answer unreadable")
	}
	// Both providers answer 200 with success=false for a bad answer;
	// anything else with no JSON verdict is the provider's failure.
	var a answer
	if jsonErr := json.Unmarshal(body, &a); jsonErr != nil || (res.StatusCode >= 500) {
		return risk.Answer{}, errx.External("CAPTCHA provider answered " + strconv.Itoa(res.StatusCode))
	}
	if res.StatusCode != http.StatusOK && len(a.ErrorCodes) == 0 && !a.Success {
		return risk.Answer{}, errx.External("CAPTCHA provider answered " + strconv.Itoa(res.StatusCode))
	}
	return risk.Answer{Success: a.Success, Hostname: a.Hostname, Action: a.Action, Codes: a.ErrorCodes, Testing: testingSecrets[secret]}, nil
}
