package authentication

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// HeadlessRequest checks the captcha_token of a headless sign-in step
// (action risk.CaptchaLogin or CaptchaSignup) before any credential work
// and returns the context the sign-in services run in: it carries the
// risk.Request (headless surface, the client's device_id, the CAPTCHA
// outcome). A nil captcha (or no CAPTCHA configured) leaves the outcome
// empty; a missing or rejected token is risk.ErrCaptchaRequired.
func HeadlessRequest(ctx context.Context, captcha Captcha, environment identity.EnvironmentID, action, token, device string) (context.Context, error) {
	request := risk.Request{Surface: risk.SurfaceHeadless, Device: device}
	if captcha != nil && !environment.IsZero() {
		outcome, err := captcha.CheckCaptcha(ctx, risk.CaptchaCheck{Environment: environment, Surface: risk.SurfaceHeadless, Token: token,
			Action: action, RemoteIP: identity.ClientInfoFrom(ctx).IP})
		if err != nil {
			return ctx, err
		}
		request.Captcha = outcome
	}
	return risk.WithRequest(ctx, request), nil
}
