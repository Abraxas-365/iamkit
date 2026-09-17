// Package impmodule assembles impersonation use cases and HTTP adapter.
package impmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authhttp"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/adapters/imphttp"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/adapters/imppg"
	"github.com/Abraxas-365/iamkit/internal/iam/impersonation/impsvc"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB     *sqlx.DB
	Tokens *authhttp.Tokens
}
type Module struct {
	Commands impersonation.Commands
	HTTP     *imphttp.Handler
}

func New(deps Deps) Module {
	service := impsvc.New(imppg.New(deps.DB))
	return Module{Commands: service, HTTP: imphttp.New(service, deps.Tokens)}
}
