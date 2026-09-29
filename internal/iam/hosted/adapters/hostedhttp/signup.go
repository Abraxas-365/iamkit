package hostedhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
)

// signupPage asks for the name, email and (when the client offers
// passwords) a password of a new account.
func (h *Handler) signupPage(c *fiber.Ctx) error {
	v, ok, err := h.base(c, h.request(c))
	if !ok {
		return err
	}
	v.Title, v.Email = v.T("hosted.title.signup"), c.Query("email")
	if !v.SignIn.Signup {
		v.Title, v.Error = v.T("hosted.title.sign_in"), v.T("hosted.error.signup_disabled")
		return render(c, fiber.StatusForbidden, "identify", v)
	}
	return render(c, fiber.StatusOK, "signup", v)
}

// signup emails the code confirming the address.
func (h *Handler) signup(c *fiber.Ctx) error {
	r := h.request(c)
	v, ok, err := h.base(c, r)
	if !ok {
		return err
	}
	v.Title, v.Email, v.Name = v.T("hosted.title.signup"), c.FormValue("email"), c.FormValue("name")
	v.Challenge, err = h.flow.Signup(c.Context(), r, v.Email, v.Name, c.FormValue("password"))
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Code == "SSO_REQUIRED" {
			// The email step routes the address to its organization's SSO.
			v.Title = v.T("hosted.title.sign_in")
			return h.retry(c, v, "identify", err)
		}
		return h.retry(c, v, "signup", err)
	}
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
	result, err := h.flow.CompleteSignup(c.Context(), r, v.Challenge, c.FormValue("code"))
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Code == "SIGNED_UP_NO_ACCESS" {
			// The account exists: nothing to retry on this page.
			status, text := failed(c, v.Lang, err)
			return render(c, status, "message", view{Lang: v.Lang, Brand: v.Brand, Title: v.T("hosted.title.signed_up"), Error: text})
		}
		return h.retry(c, v, "signup-code", err)
	}
	return h.result(c, v, result)
}
