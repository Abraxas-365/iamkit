// Package mgmtmodule assembles management authentication, control and activity adapters.
package mgmtmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtbcrypt"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtpg"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/management/mgmtsvc"
	"github.com/jmoiron/sqlx"
)

type Deps struct{ DB *sqlx.DB }
type Module struct {
	Auth     management.ManagementAuthenticator
	Sessions management.SessionCommands
	Commands management.ControlCommands
	Queries  management.ControlQueries
	HTTP     *mgmthttp.Handler
	Activity *mgmthttp.Activity
}

func New(deps Deps) Module {
	repository := mgmtpg.New(deps.DB)
	secrets := mgmtsecret.Generator{}
	passwords := mgmtbcrypt.Hasher{}
	auth := mgmtsvc.New(repository, repository, secrets, passwords)
	control := mgmtsvc.NewControl(repository, secrets)
	activity := mgmtsvc.NewActivity(repository)
	return Module{
		Auth:     auth,
		Sessions: auth,
		Commands: control,
		Queries:  control,
		HTTP:     mgmthttp.New(auth, auth, control, control),
		Activity: mgmthttp.NewActivity(activity, activity),
	}
}
