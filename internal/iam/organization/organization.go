package organization

import "encoding/json"

type Organization struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Active   bool            `json:"active"`
	Metadata json.RawMessage `json:"metadata"`
}
type Summary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Update struct {
	Name     *string         `json:"name"`
	Active   *bool           `json:"active"`
	Metadata json.RawMessage `json:"metadata"`
}
type Mutation struct{ Environment, Actor, Action, Target string }
type Membership struct {
	Organization string `json:"organization_id"`
	User         string `json:"user_id"`
	Role         string `json:"role"`
}
