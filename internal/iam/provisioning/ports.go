package provisioning

import "context"

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
type Commands interface {
	Create(context.Context, Principal, User) (User, error)
	Update(context.Context, Principal, string, Update) (User, error)
	Authenticate(context.Context, string) (Principal, error)
}
type Queries interface {
	Find(context.Context, Principal, string) (User, error)
	List(context.Context, Principal, Filter) ([]User, int, error)
}

type Repository interface {
	Authenticate(context.Context, []byte) (Principal, error)
	Find(context.Context, Principal, string) (User, error)
	List(context.Context, Principal, Filter) ([]User, int, error)
	Create(context.Context, Principal, User) error
	Update(context.Context, Principal, string, Update) (User, error)
}
type Secrets interface{ Hash(string) []byte }
