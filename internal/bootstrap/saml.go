package bootstrap

import (
	"context"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/iam/hosted"
	"github.com/Abraxas-365/iamkit/internal/iam/hosted/adapters/hostedhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp"
	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlhttp"
	"github.com/gofiber/fiber/v2"
)

// tickets routes the hosted pages' pending sign-in by ticket prefix: SAML
// tickets (samlidp.TicketPrefix) to the SAML identity provider, every other
// ticket to the OAuth authorization unchanged.
type tickets struct {
	oauth hosted.Authorizations
	saml  samlidp.Flows
}

var _ hosted.Authorizations = tickets{}

func saml(ticket string) bool { return strings.HasPrefix(ticket, samlidp.TicketPrefix) }

// Pending shows a SAML sign-in to the hosted pages as a hosted-login
// authorization without an OAuth client (zero ID): the service provider's
// environment, application and resource, the environment branding and
// every sign-in method the environment's policy allows.
func (t tickets) Pending(ctx context.Context, ticket, binding string) (oauth.Pending, error) {
	if !saml(ticket) {
		return t.oauth.Pending(ctx, ticket, binding)
	}
	target, err := t.saml.Target(ctx, ticket, binding)
	if err != nil {
		return oauth.Pending{}, err
	}
	return oauth.Pending{Client: &oauth.Client{Environment: target.Environment, Application: target.Application, Resource: target.Resource, HostedLogin: true}}, nil
}

// finisher completes a hosted sign-in: the SAML response for SAML tickets,
// the OAuth authorization otherwise.
func finisher(oauthFinish hostedhttp.Finisher, samlHTTP *samlhttp.Handler) hostedhttp.Finisher {
	return func(c *fiber.Ctx, ticket string, login oauth.Login) error {
		if !saml(ticket) {
			return oauthFinish(c, ticket, login)
		}
		return samlHTTP.Finish(c, ticket, samlidp.Login{User: login.User, Organization: login.Organization, Session: login.Session, Permissions: login.Permissions})
	}
}
