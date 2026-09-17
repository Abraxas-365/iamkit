package appmodule

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/application"
	"github.com/jmoiron/sqlx"
)

func TestModuleExposesUseCasePorts(t *testing.T) {
	module := New(Deps{DB: &sqlx.DB{}})
	if module.Commands == nil || module.Queries == nil || module.HTTP == nil {
		t.Fatal("application module did not expose assembled capabilities")
	}
	if _, ok := module.Commands.(application.Commands); !ok {
		t.Fatal("commands port is not exposed")
	}
	if _, ok := module.Queries.(application.Queries); !ok {
		t.Fatal("queries port is not exposed")
	}
}
