package oauthhttp

import (
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/gofiber/fiber/v2"
	"github.com/ory/fosite"
)

// PublicClientLocal is the fiber local the token and revocation endpoints
// set to true once the request's client is public (no secret, auth none):
// only then may any browser origin read the answer (server CORS).
const PublicClientLocal = "iamkit.oauth.public_client"

// markPublic records a public client for the CORS layer.
func markPublic(c *fiber.Ctx, client *oauth.Client) {
	if client.Public && client.Auth.Method == identity.AuthNone {
		c.Locals(PublicClientLocal, true)
	}
}

// invalidTarget is the RFC 8707 error fosite has no constant for.
func invalidTarget(err error) *fosite.RFC6749Error {
	hint := "The requested resource is not one this client may access."
	var e *errx.Error
	if errx.As(err, &e) {
		hint = e.Message
	}
	return &fosite.RFC6749Error{ErrorField: oauth.CodeInvalidTarget, DescriptionField: "The requested resource is invalid, unknown, or malformed.", HintField: hint, CodeField: 400}
}

// resourceGrant reports whether a token request of grant may carry the
// RFC 8707 resource parameter IAMKit resolves.
func resourceGrant(grant string) bool {
	return grant == "authorization_code" || grant == "refresh_token"
}

// grantResource checks the resource values of a code or refresh request
// against the grant: a plain grant names none; a resource grant may repeat
// its own (canonically) or omit it, and ends when its client's protected
// resource is gone.
func grantResource(client *oauth.Client, session *oauthfosite.Session, values []string) error {
	if session.Resource == "" {
		return invalidTarget(oauth.ErrInvalidTarget("this grant was not issued for a resource"))
	}
	if client.Protected == nil || !oauth.SameResource(session.Resource, client.Protected.URI) {
		return endedGrant
	}
	if len(values) > 1 {
		return invalidTarget(oauth.ErrInvalidTarget("only one resource may be requested"))
	}
	if len(values) == 1 && !oauth.SameResource(values[0], session.Resource) {
		return invalidTarget(oauth.ErrInvalidTarget("the resource is not the one this grant was issued for"))
	}
	return nil
}

// grantScopes replaces the request's granted scopes (fosite only appends).
func grantScopes(r fosite.Requester, scopes []string) {
	switch req := r.(type) {
	case *fosite.AccessRequest:
		req.GrantedScope = fosite.Arguments(scopes)
	case *fosite.AuthorizeRequest:
		req.GrantedScope = fosite.Arguments(scopes)
	}
}
