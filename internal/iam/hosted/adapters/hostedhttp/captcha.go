package hostedhttp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// deviceCookie carries the browser's device identifier (128 random bits)
// that risk evaluation hashes into user_devices.
const deviceCookie = "__Host-iamkit-device"

// widget is the provider's CAPTCHA widget a page renders: its script and
// element, and the hosts its content security policy admits.
type widget struct {
	Provider string
	SiteKey  string
	Action   string
	// Class is the element class the provider's script looks for; Script
	// the script URL; Field the form field the widget fills in.
	Class, Script, Field string
	// scripts, frames and connects are the CSP sources the provider needs.
	scripts, frames, connects, styles string
}

func widgetOf(p risk.PublicCaptcha, action string) *widget {
	switch p.Provider {
	case risk.ProviderTurnstile:
		const host = "https://challenges.cloudflare.com"
		return &widget{Provider: p.Provider, SiteKey: p.SiteKey, Action: action, Class: "cf-turnstile", Script: host + "/turnstile/v0/api.js", Field: "cf-turnstile-response",
			scripts: host, frames: host, connects: host}
	case risk.ProviderHCaptcha:
		const hosts = "https://hcaptcha.com https://*.hcaptcha.com"
		return &widget{Provider: p.Provider, SiteKey: p.SiteKey, Action: action, Class: "h-captcha", Script: "https://js.hcaptcha.com/1/api.js", Field: "h-captcha-response",
			scripts: hosts, frames: hosts, connects: hosts, styles: hosts}
	}
	return nil
}

// field is the form field a provider's widget fills in.
func field(provider string) string {
	if w := widgetOf(risk.PublicCaptcha{Provider: provider}, ""); w != nil {
		return w.Field
	}
	return ""
}

// policy is the content security policy a page with the widget adds: the
// provider's hosts on script-src, frame-src and connect-src (and
// style-src for hCaptcha), after what the page already allows.
func (w *widget) policy(nonce string, scripted bool) string {
	connect := w.connects
	if scripted {
		connect = "'self' " + w.connects
	}
	out := "; script-src 'nonce-" + nonce + "' " + w.scripts + "; frame-src " + w.frames + "; connect-src " + connect
	return out
}

// Captcha enables the CAPTCHA of the identify, sign-up and device pages and
// the pass later pages check (nil: pages never show one).
func (h *Handler) Captcha(captcha hosted.Captcha) { h.captcha = captcha }

// ticketHash is what hosted_captcha_passes keeps of a ticket.
func ticketHash(ticket string) []byte {
	sum := sha256.Sum256([]byte(ticket))
	return sum[:]
}

// deviceID is the browser's device identifier: its cookie, or a new one
// set on the response.
func deviceID(c *fiber.Ctx) string {
	if id := c.Cookies(deviceCookie); risk.ValidDevice(id) {
		return id
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	id := hex.EncodeToString(raw)
	c.Cookie(&fiber.Cookie{Name: deviceCookie, Value: id, Path: "/", Secure: true, HTTPOnly: true, SameSite: "Lax", MaxAge: int(config.DeviceCookieMaxAge.Seconds())})
	return id
}

// arm prepares a ticket's page: the device cookie, whether the
// environment's CAPTCHA applies and whether the ticket already holds a
// pass, and the risk request the sign-in services read from the context.
func (h *Handler) arm(c *fiber.Ctx, v *view, environment identity.EnvironmentID, ticket string) {
	v.Environment, v.device = environment, deviceID(c)
	if h.captcha != nil {
		ctx := c.UserContext()
		pub, err := h.captcha.PublicCaptcha(ctx, environment, risk.SurfaceHosted)
		switch {
		case err != nil:
			// The configuration could not be read: credential posts are
			// refused rather than let through without the CAPTCHA.
			v.captchaErr = err
		case pub.Enabled:
			v.pub = &pub
			passed, err := h.captcha.Passed(ctx, environment, ticketHash(ticket))
			v.passed = err == nil && passed
		}
	}
	h.bind(c, *v)
}

// bind puts the risk request of the page's journey in the context.
func (h *Handler) bind(c *fiber.Ctx, v view) {
	req := risk.Request{Surface: risk.SurfaceHosted, Device: v.device}
	if v.passed {
		req.Captcha = risk.CaptchaPassed
	}
	if v.unavailable {
		req.Captcha = risk.CaptchaUnavailable
	}
	c.SetUserContext(risk.WithRequest(c.UserContext(), req))
}

// show makes the page render the widget for action when the CAPTCHA
// applies and the ticket has no pass yet.
func (v *view) show(action string) {
	if v.pub != nil && !v.passed {
		v.Captcha = widgetOf(*v.pub, action)
	}
}

// solve verifies the widget's answer of an identify or sign-up submission
// and leaves a pass on the ticket (also when the provider could not be
// reached: it fails open). A missing or rejected answer is
// risk.ErrCaptchaRequired.
func (h *Handler) solve(c *fiber.Ctx, v *view, ticket, action string) error {
	if v.captchaErr != nil {
		return v.captchaErr
	}
	if v.pub == nil || v.passed {
		return nil
	}
	out, err := h.captcha.CheckCaptcha(c.UserContext(), risk.CaptchaCheck{Environment: v.Environment, Surface: risk.SurfaceHosted,
		Token: c.FormValue(field(v.pub.Provider)), Action: action, RemoteIP: identity.ClientInfoFrom(c.UserContext()).IP})
	if err != nil {
		return err
	}
	if out == "" {
		return nil
	}
	v.passed, v.unavailable = true, out == risk.CaptchaUnavailable
	if err := h.captcha.GrantPass(c.UserContext(), v.Environment, ticketHash(ticket)); err != nil {
		slog.Warn("hosted login: CAPTCHA pass not stored", "err", err)
	}
	h.bind(c, *v)
	return nil
}

// needPass refuses a credential step whose ticket holds no live pass and
// spends one of the pass's uses (config.CaptchaPassUses): the journey goes
// back to the identify page, which shows the widget again.
func (h *Handler) needPass(c *fiber.Ctx, v *view, ticket string) error {
	if v.captchaErr != nil {
		return v.captchaErr
	}
	if v.pub == nil {
		return nil
	}
	if v.passed {
		ok, err := h.captcha.UsePass(c.UserContext(), v.Environment, ticketHash(ticket))
		if err != nil {
			return err
		}
		v.passed = ok
	}
	if !v.passed {
		return risk.ErrCaptchaRequired(v.pub.Provider)
	}
	return nil
}
