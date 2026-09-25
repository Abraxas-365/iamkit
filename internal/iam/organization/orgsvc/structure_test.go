package orgsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/organization"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type unitRepository struct {
	organization.StructureRepository
	id     identity.UnitID
	create bool
}

func (r *unitRepository) SaveUnit(_ context.Context, _ organization.Boundary, _ organization.Mutation, id identity.UnitID, _ organization.Unit, create bool) error {
	r.id, r.create = id, create
	return nil
}

// SaveUnit must tell the repository to INSERT when no id is given; generating
// the id first and then testing IsZero() made every create an UPDATE (404).
func TestSaveUnitCreateVersusUpdate(t *testing.T) {
	input := organization.Unit{Name: "Europe", Kind: "region"}

	repo := &unitRepository{}
	id, err := NewStructure(repo).SaveUnit(context.Background(), organization.Boundary{}, organization.Mutation{}, identity.UnitID{}, input)
	if err != nil || id.IsZero() || repo.id != id || !repo.create {
		t.Fatalf("create: id=%v err=%v repo=%+v", id, err, repo)
	}

	existing := identity.NewUnitID()
	repo = &unitRepository{}
	id, err = NewStructure(repo).SaveUnit(context.Background(), organization.Boundary{}, organization.Mutation{}, existing, input)
	if err != nil || id != existing || repo.create {
		t.Fatalf("update: id=%v err=%v repo=%+v", id, err, repo)
	}
}
