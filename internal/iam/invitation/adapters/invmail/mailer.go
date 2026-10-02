// Package invmail delivers invitations through the authentication delivery
// webhooks (per-environment, falling back to the global one).
package invmail

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/invitation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Sender is the part of the authentication delivery service invitations use.
type Sender interface {
	Send(ctx context.Context, environment identity.EnvironmentID, message authentication.Message) error
	InvitationURL(ctx context.Context, environment identity.EnvironmentID) (string, error)
}

type Mailer struct{ Sender Sender }

var _ invitation.Mailer = Mailer{}

func (m Mailer) Send(ctx context.Context, environment identity.EnvironmentID, mail invitation.Mail) error {
	expires := mail.ExpiresAt
	return m.Sender.Send(ctx, environment, authentication.Message{
		Email: mail.Email, Purpose: "invitation", Token: mail.Token, Link: mail.Link,
		Organization: mail.Organization, OrganizationID: mail.OrganizationID, Inviter: mail.Inviter, ExpiresAt: &expires,
	})
}

func (m Mailer) Link(ctx context.Context, environment identity.EnvironmentID, token string) (string, error) {
	base, err := m.Sender.InvitationURL(ctx, environment)
	return authentication.InvitationLink(base, token), err
}
