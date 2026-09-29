package samlidp

import (
	"context"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Commands manage an environment's service providers; every change is
// audited.
type Commands interface {
	Create(ctx context.Context, m Mutation, input Create) (ServiceProvider, error)
	Update(ctx context.Context, m Mutation, provider identity.ServiceProviderID, input Update) (ServiceProvider, error)
	Delete(ctx context.Context, m Mutation, provider identity.ServiceProviderID) error
}

// Queries read service providers and the identity provider settings they
// are configured with.
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, page query.Pagination) (query.Paginated[ServiceProvider], error)
	Find(ctx context.Context, environment identity.EnvironmentID, provider identity.ServiceProviderID) (ServiceProvider, error)
	IdentityProvider(ctx context.Context, environment identity.EnvironmentID) (IdentityProvider, error)
}

// Flows are the browser single sign-on steps.
type Flows interface {
	// Metadata is the environment's IdP metadata document.
	Metadata(ctx context.Context, environment identity.EnvironmentID) ([]byte, error)
	// Begin checks an AuthnRequest and parks it for the hosted sign-in:
	// it returns the ik_samlreq_ ticket and the browser binding secret.
	Begin(ctx context.Context, environment identity.EnvironmentID, message Message) (ticket string, binding string, err error)
	// Target is the application a parked request signs in to (the hosted
	// pages' view of the ticket).
	Target(ctx context.Context, ticket, binding string) (Target, error)
	// Finish answers the parked request with a signed response for the
	// login's session; the ticket is used once.
	Finish(ctx context.Context, ticket, binding string, login Login) (Response, error)
}

// Repository stores service providers and parked requests.
type Repository interface {
	// Create, Update and Delete audit m in the same transaction.
	Create(ctx context.Context, m Mutation, provider ServiceProvider) error
	Update(ctx context.Context, m Mutation, provider identity.ServiceProviderID, input Update) error
	Delete(ctx context.Context, m Mutation, provider identity.ServiceProviderID) error
	Find(ctx context.Context, environment identity.EnvironmentID, provider identity.ServiceProviderID) (ServiceProvider, error)
	// FindEntity finds the provider with an entity ID.
	FindEntity(ctx context.Context, environment identity.EnvironmentID, entity string) (ServiceProvider, error)
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, page query.Pagination) (query.Paginated[ServiceProvider], error)
	// EnvironmentExists reports whether the environment exists.
	EnvironmentExists(ctx context.Context, environment identity.EnvironmentID) (bool, error)
	SaveRequest(ctx context.Context, ticket, binding []byte, environment identity.EnvironmentID, request Request) error
	// PendingRequest is an unexpired, unused parked request.
	PendingRequest(ctx context.Context, ticket []byte) (Pending, error)
	// ConsumeRequest marks the request used and audits m; a request
	// already used is refused.
	ConsumeRequest(ctx context.Context, m Mutation, ticket []byte) error
	// Subject is the user's email address and name.
	Subject(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (Subject, error)
}

// Protocol reads and writes SAML messages with the environment's key.
type Protocol interface {
	// Decode reads an AuthnRequest (its XML is not trusted yet).
	Decode(message Message) (AuthnRequest, error)
	IdentityProvider(ctx context.Context, environment identity.EnvironmentID) (IdentityProvider, error)
	Metadata(ctx context.Context, environment identity.EnvironmentID) ([]byte, error)
	// Respond signs a response carrying the assertion.
	Respond(ctx context.Context, environment identity.EnvironmentID, provider ServiceProvider, request Request, assertion Assertion) (Response, error)
}

// Secrets generate and hash tickets.
type Secrets interface {
	Generate(prefix string) (string, []byte, error)
	Hash(raw string) []byte
}
