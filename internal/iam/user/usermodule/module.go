// Package usermodule assembles user persistence, use cases and HTTP entry adapter.
package usermodule

import (
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userkeys"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userpg"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userschema"
	"github.com/Abraxas-365/iamkit/internal/iam/user/usersvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

// Passwords hashes new passwords and checks imported hashes against the
// formats sign-in verifies (and rehashes).
type Passwords interface {
	user.PasswordHasher
	user.PasswordHashes
}

type Deps struct {
	DB        *sqlx.DB
	Passwords Passwords
	ActorID   func(*fiber.Ctx) string
	// PasswordPolicy checks new passwords; nil checks only the length.
	PasswordPolicy user.PasswordPolicy
	// SMS texts phone verification codes; nil disables /identity/v1/me/phone.
	SMS user.SMS
	// Actions runs request:user.* hooks (nil: none).
	Actions user.Actions
	// Quota enforces the users limit (nil: none).
	Quota user.Quota
}
type Module struct {
	Commands user.Commands
	Queries  user.Queries
	HTTP     *userhttp.Handler
	// KeyCommands/KeyQueries manage machine users' keys (JWT-bearer
	// login); Keys serves them to operators.
	KeyCommands user.KeyCommands
	KeyQueries  user.KeyQueries
	Keys        *userhttp.Keys
	// Phones is self-service phone verification (nil without Deps.SMS).
	Phones user.PhoneCommands
}

func New(deps Deps) Module {
	repository := userpg.New(deps.DB)
	// One hasher writes new passwords and checks imported hashes against
	// the formats sign-in verifies (and rehashes).
	service := usersvc.New(repository, deps.Passwords, userschema.Validator{})
	service.SetPasswordHashes(deps.Passwords)
	if deps.PasswordPolicy != nil {
		service.SetPasswordPolicy(deps.PasswordPolicy)
	}
	if deps.Actions != nil {
		service.SetActions(deps.Actions)
	}
	if deps.Quota != nil {
		service.SetQuota(deps.Quota)
	}
	keys := usersvc.NewKeys(repository, userkeys.RSA{})
	handler := userhttp.New(service, service, deps.ActorID)
	var phones user.PhoneCommands
	if deps.SMS != nil {
		phones = usersvc.NewPhones(repository, deps.SMS, cryptox.Generator{})
		handler.SetPhones(phones)
	}
	return Module{
		Commands: service, Queries: service, HTTP: handler, Phones: phones,
		KeyCommands: keys, KeyQueries: keys,
		Keys: userhttp.NewKeys(keys, keys, deps.ActorID),
	}
}
