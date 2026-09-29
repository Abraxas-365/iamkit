package oauthsvc

import (
	"context"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// ExchangeResource is RFC 8693 token exchange for another resource of the
// subject token's application: same user, organization and sign-in, the
// user's permissions on the target resource (optionally narrowed by
// scope), in a child session that ends with the original one.
func (s *Service) ExchangeResource(ctx context.Context, client *oauth.Client, input oauth.Exchange) (oauth.Exchanged, error) {
	if client.Public || !client.Allows(oauth.GrantTokenExchange) {
		return oauth.Exchanged{}, oauth.ExchangeError(oauth.ExchangeUnauthorizedClient, "the client may not exchange tokens")
	}
	if err := input.Validate(client); err != nil {
		return oauth.Exchanged{}, err
	}
	session, err := s.repository.ExchangeSession(ctx, client, input.Subject, input.Audience, identity.NewSessionID())
	if err != nil {
		return oauth.Exchanged{}, err
	}
	if len(input.Scope) > 0 {
		if !identity.Subset(input.Scope, session.Permissions) {
			return oauth.Exchanged{}, oauth.ExchangeError(oauth.ExchangeInvalidScope, "scope must name permissions the user has on the target resource")
		}
		session.Permissions = input.Scope
	}
	return oauth.Exchanged{Token: session.Token(), Audience: session.Audience}, nil
}

// Impersonate issues a user's access token to a service account allowed to
// impersonate (service_accounts.can_impersonate), for the account's own
// application and resource, in a new session attributed to the account.
func (s *Service) Impersonate(ctx context.Context, input oauth.Impersonation) (oauth.Exchanged, error) {
	if input.Account.IsZero() {
		return oauth.Exchanged{}, oauth.ExchangeError(oauth.ExchangeUnauthorizedClient, "a service account is required")
	}
	if err := input.Validate(); err != nil {
		return oauth.Exchanged{}, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	session, err := s.repository.ImpersonationSession(ctx, input, identity.NewSessionID(), time.Now().Add(config.ImpersonationTokenTTL))
	if err != nil {
		return oauth.Exchanged{}, err
	}
	return oauth.Exchanged{Token: session.Token(), Audience: session.Audience}, nil
}

var _ oauth.Exchanges = (*Service)(nil)
