// Package featuremodule assembles feature flags. It is imported only by
// the composition root.
package featuremodule

import (
	"github.com/Abraxas-365/iamkit/internal/cache"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
	"github.com/Abraxas-365/iamkit/internal/iam/feature/adapters/featurehttp"
	"github.com/Abraxas-365/iamkit/internal/iam/feature/adapters/featurepg"
	"github.com/Abraxas-365/iamkit/internal/iam/feature/featuresvc"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

type Deps struct {
	DB *sqlx.DB
	// Deployment holds IAMKIT_FEATURES.
	Deployment feature.Deployment
	// Cache keeps overrides (REDIS_URL; nil: none).
	Cache   cache.Store
	ActorID func(*fiber.Ctx) string
}

type Module struct {
	Commands feature.Commands
	Queries  feature.Queries
	HTTP     *featurehttp.Handler
}

func New(deps Deps) Module {
	service := featuresvc.New(featurepg.New(deps.DB), deps.Deployment)
	service.SetCache(deps.Cache)
	return Module{Commands: service, Queries: service, HTTP: featurehttp.New(service, service, deps.ActorID)}
}
