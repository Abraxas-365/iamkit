package organization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Boundary struct{ Environment, Organization string }
type Unit struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	Parent *string `json:"parent_id"`
}

// Validate checks the structural invariants Unit owns.
func (u Unit) Validate() error {
	if strings.TrimSpace(u.Name) == "" {
		return errx.Validation("unit name is required")
	}
	if strings.TrimSpace(u.Kind) == "" {
		return errx.Validation("unit kind is required")
	}
	if u.Parent != nil && !identity.ValidID(*u.Parent) {
		return errx.Validation("parent_id must be a valid UUID")
	}
	return nil
}

type Profile struct {
	Unit    *string `json:"org_unit_id"`
	Manager *string `json:"manager_id"`
}

// Validate checks only the fields explicitly supplied.
func (p Profile) Validate() error {
	if p.Unit != nil && !identity.ValidID(*p.Unit) {
		return errx.Validation("org_unit_id must be a valid UUID")
	}
	if p.Manager != nil && !identity.ValidID(*p.Manager) {
		return errx.Validation("manager_id must be a valid UUID")
	}
	return nil
}

type Position struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

// Validate checks the structural invariants Position owns.
func (p Position) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errx.Validation("position name is required")
	}
	if strings.TrimSpace(p.Code) == "" {
		return errx.Validation("position code is required")
	}
	return nil
}

type Assignment struct {
	Position string  `json:"position_id"`
	User     string  `json:"user_id"`
	Unit     *string `json:"org_unit_id"`
}

// Validate checks the structural invariants Assignment owns.
func (a Assignment) Validate() error {
	if !identity.ValidID(a.Position) {
		return errx.Validation("position_id must be a valid UUID")
	}
	if !identity.ValidID(a.User) {
		return errx.Validation("user_id must be a valid UUID")
	}
	if a.Unit != nil && !identity.ValidID(*a.Unit) {
		return errx.Validation("org_unit_id must be a valid UUID")
	}
	return nil
}

// StructureView identifies bounded read models, never SQL supplied by callers.
type StructureView string

const (
	Members      StructureView = "members"
	Units        StructureView = "units"
	Positions    StructureView = "positions"
	Assignments  StructureView = "assignments"
	UnitDetail   StructureView = "unit"
	Ancestors    StructureView = "ancestors"
	Descendants  StructureView = "descendants"
	DeleteImpact StructureView = "delete-impact"
	Tree         StructureView = "tree"
	Chart        StructureView = "chart"
)
