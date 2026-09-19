package provisioning

import "github.com/Abraxas-365/iamkit/internal/identity"

type Principal struct {
	ID           identity.CredentialID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Connection   identity.ConnectionID
}
type User struct {
	ID       identity.UserID
	Email    string
	Name     string
	External string
	Manager  string
	Active   bool
}
type Update struct {
	Name    *string
	Active  *bool
	Manager *string
}
type Filter struct {
	Field, Value string
	Start, Count int
}
