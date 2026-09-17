package application

// Application is the environment-scoped client application model.
// It is independent of HTTP and PostgreSQL representations.
type Application struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
	Active    bool     `json:"active"`
}

// Create is the data required to register an application.
type Create struct {
	Name      string   `json:"name"`
	Redirects []string `json:"redirect_uris"`
}

// Update contains only fields explicitly supplied by an administrator.
type Update struct {
	Name      *string   `json:"name"`
	Redirects *[]string `json:"redirect_uris"`
	Active    *bool     `json:"active"`
}

// Mutation is immutable audit context supplied by the management boundary.
type Mutation struct{ Environment, Actor, Action, Target string }
