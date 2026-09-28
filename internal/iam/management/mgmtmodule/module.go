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

type Deps struct {
	DB *sqlx.DB
	// SSO configures operator sign-in (validated by the caller); nil means
	// password sign-in only.
	SSO *SSO
}

// SSO is the operator sign-in configuration and the port that reaches the
// configured identity providers.
type SSO struct {
	Settings management.SSOSettings
	Provider management.IdentityProvider
}

type Module struct {
	Auth     management.ManagementAuthenticator
	Sessions management.SessionCommands
	Commands management.ControlCommands
	Queries  management.ControlQueries
	HTTP     *mgmthttp.Handler
	Activity *mgmthttp.Activity
	// SSOHTTP serves the login options, operator single sign-on and the
	// linked identities of operators.
	SSOHTTP *mgmthttp.SSO
}

func New(deps Deps) Module {
	repository := mgmtpg.New(deps.DB)
	secrets := mgmtsecret.Generator{}
	passwords := mgmtbcrypt.Hasher{}
	auth := mgmtsvc.New(repository, repository, secrets, passwords)
	control := mgmtsvc.NewControl(repository, secrets)
	activity := mgmtsvc.NewActivity(repository)
	settings := management.SSOSettings{Password: management.PasswordEnabled}
	var provider management.IdentityProvider
	if deps.SSO != nil {
		settings, provider = deps.SSO.Settings, deps.SSO.Provider
	}
	auth.WithPasswordMode(settings.Password)
	sso := mgmtsvc.NewSSO(settings, provider, repository, repository, secrets)
	return Module{
		Auth:     auth,
		Sessions: auth,
		Commands: control,
		Queries:  control,
		HTTP:     mgmthttp.New(auth, auth, auth, control, control),
		Activity: mgmthttp.NewActivity(activity, activity),
		SSOHTTP:  mgmthttp.NewSSO(sso, sso, sso),
	}
}
