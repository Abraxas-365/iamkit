package authentication

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

// FederationLink is a SAML identity provider's view of the session a
// SAML sign-in opens: the connection, the NameID (and its format) the
// assertion named and its SessionIndex. Stored with the session
// (federation_sessions) so that the identity provider's LogoutRequest can
// find it and an SP-initiated logout can name it back. Only SAML
// connections set it; it is nil for every other sign-in.
type FederationLink struct {
	Connection   identity.ConnectionID `json:"connection_id"`
	NameID       string                `json:"name_id"`
	NameIDFormat string                `json:"name_id_format,omitempty"`
	SessionIndex string                `json:"session_index,omitempty"`
}

// Valid reports whether the link names a connection and a subject.
func (l *FederationLink) Valid() bool {
	return l != nil && !l.Connection.IsZero() && l.NameID != "" && len(l.NameID) <= 1024 && len(l.SessionIndex) <= 1024
}

type federationKey struct{}

// WithFederationLink carries the SAML link of the sign-in being finished
// in the context (like risk.WithDecision), so the session writer
// (authpg.CreateSession) stores it without new parameters. An invalid or
// nil link is dropped.
func WithFederationLink(ctx context.Context, link *FederationLink) context.Context {
	if !link.Valid() {
		return ctx
	}
	copied := *link
	return context.WithValue(ctx, federationKey{}, &copied)
}

// FederationLinkFrom returns the link WithFederationLink stored (nil when
// none).
func FederationLinkFrom(ctx context.Context) *FederationLink {
	link, _ := ctx.Value(federationKey{}).(*FederationLink)
	return link
}
