package oauth

import "context"

// ClientRepository loads only clients whose registration and application are active.
// Environment is explicit on every lookup; IDs alone never establish authority.
type ClientRepository interface {
	FindActive(ctx context.Context, environment, id string) (*Client, error)
}
