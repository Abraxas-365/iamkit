// Package sacctmodule assembles service-account use cases and HTTP adapter.
package sacctmodule

import (
	"github.com/Abraxas-365/iamkit/internal/iam/management/adapters/mgmtsecret"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/saccthttp"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/adapters/sacctpg"
	"github.com/Abraxas-365/iamkit/internal/iam/serviceaccount/sacctsvc"
	"github.com/jmoiron/sqlx"
)

type Deps struct{ DB *sqlx.DB }
type Module struct {
	Commands serviceaccount.Commands
	Queries  serviceaccount.Queries
	HTTP     *saccthttp.Handler
}

func New(deps Deps) Module {
	service := sacctsvc.New(sacctpg.New(deps.DB), mgmtsecret.Generator{})
	return Module{Commands: service, Queries: service, HTTP: saccthttp.New(service, service)}
}
