package bootstrap

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// upstreamLogout adapts federation's SAML single logout to the oauth
// module's UpstreamLogout port (oauth imports no federation package).
type upstreamLogout struct{ flows federation.LogoutFlows }

func (u upstreamLogout) BeginLogout(ctx context.Context, environment identity.EnvironmentID, session identity.SessionID, back string) (string, [][2]string, bool, error) {
	out, ok, err := u.flows.BeginLogout(ctx, environment, session, back)
	if err != nil || !ok {
		return "", nil, false, err
	}
	return out.URL, out.Fields, true, nil
}
