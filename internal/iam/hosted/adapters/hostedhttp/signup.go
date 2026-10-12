package hostedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// signupPage asks for the name, email and (when the client offers
// passwords) a password of a new account.
func (h *Handler) signupPage(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.signup"), c.Query("email")
	if !v.SignIn.Signup {
		v.Title, v.Error = v.T("hosted.title.sign_in"), v.T("hosted.error.signup_disabled")
		return render(c, fiber.StatusForbidden, "identify", v)
	}
	if token := c.Query("waitlist"); token != "" {
		// The approval link prefills its address; a token that does not
		// resolve shows the plain form and says nothing about why.
		if email, err := h.flow.WaitlistEmail(c.UserContext(), r, token); err == nil {
			v.Waitlist, v.Email = token, email
		}
	}
	v.show(risk.CaptchaSignup)
	return render(c, fiber.StatusOK, "signup", v)
}

// signup emails the code confirming the address, or tells the person they
// are on the waitlist.
func (h *Handler) signup(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email, v.Name, v.Waitlist = v.T("hosted.title.signup"), c.FormValue("email"), c.FormValue("name"), c.FormValue("waitlist")
	if err := h.solve(c, &v, r.Ticket, risk.CaptchaSignup); err != nil {
		status, text := failed(c, v, err)
		v.Error = text
		v.show(risk.CaptchaSignup)
		return render(c, status, "signup", v)
	}
	out, err := h.flow.Signup(c.UserContext(), r, v.Email, v.Name, c.FormValue("password"), v.Waitlist, c.FormValue("accept_terms") == "on")
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Code == "SSO_REQUIRED" {
			// The email step routes the address to its organization's SSO.
			v.Title = v.T("hosted.title.sign_in")
			return h.retry(c, v, "identify", err)
		}
		v.show(risk.CaptchaSignup)
		return h.retry(c, v, "signup", err)
	}
	if out.Status == authentication.SignupWaitlisted {
		v.Title, v.Notice = v.T("hosted.title.waitlisted"), v.T("hosted.notice.waitlisted", v.Email)
		return render(c, fiber.StatusOK, "waitlisted", v)
	}
	v.Challenge = out.Challenge
	v.Title, v.Notice = v.T("hosted.title.check_email"), v.T("hosted.notice.signup_sent", v.Email)
	return render(c, fiber.StatusOK, "signup-code", v)
}

// completeSignup creates the account and continues the sign-in.
func (h *Handler) completeSignup(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.check_email"), c.FormValue("email")
	v.Challenge, _ = identity.ParseChallengeID(c.FormValue("challenge_id"))
	result, err := h.flow.CompleteSignup(c.UserContext(), r, v.Challenge, c.FormValue("code"))
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Code == "SIGNED_UP_NO_ACCESS" {
			// The account exists: nothing to retry on this page.
			status, text := failed(c, v, err)
			return render(c, status, "message", view{Lang: v.Lang, Texts: v.Texts, Brand: v.Brand, Title: v.T("hosted.title.signed_up"), Error: text})
		}
		return h.retry(c, v, "signup-code", err)
	}
	return h.result(c, v, result)
}
