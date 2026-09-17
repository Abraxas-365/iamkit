// Package mgmtmodule assembles management authentication, control and activity adapters.
package mgmtmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtpg"
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/management/mgmtsvc"
	"github.com/jmoiron/sqlx"
)

type Deps struct{ DB *sqlx.DB }
type Module struct {
	Auth     management.ManagementAuthenticator
	Commands management.ControlCommands
	Queries  management.ControlQueries
	HTTP     *mgmthttp.Handler
	Activity *mgmthttp.Activity
}

func New(deps Deps) Module {
	repository := mgmtpg.New(deps.DB)
	auth := mgmtsvc.New(repository, mgmtsecret.Generator{})
	control := mgmtsvc.NewControl(repository, mgmtsecret.Generator{})
	activity := mgmtsvc.NewActivity(repository)
	return Module{Auth: auth, Commands: control, Queries: control, HTTP: mgmthttp.New(auth, control, control), Activity: mgmthttp.NewActivity(activity, activity)}
}
