package bootstrap

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// hostedCaptcha is hosted.Captcha: the risk module's queries (widget, check,
// pass lookup) and the command that records a pass.
type hostedCaptcha struct {
	risk.CaptchaQueries
	commands risk.CaptchaCommands
}

func (h hostedCaptcha) GrantPass(ctx context.Context, environment identity.EnvironmentID, ticket []byte) error {
	return h.commands.GrantPass(ctx, environment, ticket)
}

func (h hostedCaptcha) UsePass(ctx context.Context, environment identity.EnvironmentID, ticket []byte) (bool, error) {
	return h.commands.UsePass(ctx, environment, ticket)
}
