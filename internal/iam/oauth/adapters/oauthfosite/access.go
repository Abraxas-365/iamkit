package oauthfosite

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/jmoiron/sqlx"
)

// AccessTokens answers whether an OAuth-issued access token is still live.
// It lives beside Store because this package owns the oauth_requests layout
// and the signature hashing; it satisfies authentication.OAuthTokens.
type AccessTokens struct{ DB *sqlx.DB }

// Active reports true only while the token's access grant row is active and
// unexpired and its client is still enabled. Revoking the grant family
// (refresh/code replay) therefore invalidates already-issued access tokens.
func (a AccessTokens) Active(ctx context.Context, environment identity.EnvironmentID, client identity.ClientID, signature string) (bool, error) {
	var live bool
	err := a.DB.GetContext(ctx, &live, `SELECT EXISTS(
  SELECT 1 FROM oauth_requests r
  JOIN oauth_clients c ON c.id=r.client_id AND c.environment_id=r.environment_id
  WHERE r.environment_id=$1 AND r.kind='access' AND r.signature_hash=$2 AND r.client_id=$3
    AND r.active AND r.expires_at>clock_timestamp() AND c.active)`, environment, SignatureHash(signature), client)
	return live, wrap(err, "check OAuth access token")
}
