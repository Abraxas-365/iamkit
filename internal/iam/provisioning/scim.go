package provisioning

// Principal identifies an authenticated SCIM provisioning credential.
type Principal struct{ ID, Environment, Organization, Connection string }
type User struct {
	ID, Email, Name, External, Manager string
	Active                             bool
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
