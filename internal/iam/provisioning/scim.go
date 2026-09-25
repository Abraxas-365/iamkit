package provisioning

import "github.com/Abraxas-365/iamkit/internal/identity"

type Principal struct {
	ID           identity.CredentialID
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
	Connection   identity.ConnectionID
}
type User struct {
	ID       identity.UserID `db:"id"`
	Email    string          `db:"email"`
	Name     string          `db:"name"`
	External string          `db:"external_id"`
	Manager  string          `db:"manager_id"`
	Active   bool            `db:"active"`
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
