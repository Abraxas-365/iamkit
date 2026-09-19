package organization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Boundary struct {
	Environment  identity.EnvironmentID
	Organization identity.OrganizationID
}
type Unit struct {
	Name   string           `json:"name"`
	Kind   string           `json:"kind"`
	Parent *identity.UnitID `json:"parent_id"`
}

func (u Unit) Validate() error {
	if strings.TrimSpace(u.Name) == "" {
		return errx.Validation("unit name is required")
	}
	if strings.TrimSpace(u.Kind) == "" {
		return errx.Validation("unit kind is required")
	}
	if u.Parent != nil && u.Parent.IsZero() {
		return errx.Validation("parent_id must be a valid UUID")
	}
	return nil
}

type Profile struct {
	Unit    *identity.UnitID `json:"org_unit_id"`
	Manager *identity.UserID `json:"manager_id"`
}

func (p Profile) Validate() error {
	if p.Unit != nil && p.Unit.IsZero() {
		return errx.Validation("org_unit_id must be a valid UUID")
	}
	if p.Manager != nil && p.Manager.IsZero() {
		return errx.Validation("manager_id must be a valid UUID")
	}
	return nil
}

type Position struct {
	Name string `json:"name"`
	Code string `json:"code"`
}

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
	Position identity.PositionID `json:"position_id"`
	User     identity.UserID     `json:"user_id"`
	Unit     *identity.UnitID    `json:"org_unit_id"`
}

func (a Assignment) Validate() error {
	if a.Position.IsZero() {
		return errx.Validation("position_id must be a valid UUID")
	}
	if a.User.IsZero() {
		return errx.Validation("user_id must be a valid UUID")
	}
	if a.Unit != nil && a.Unit.IsZero() {
		return errx.Validation("org_unit_id must be a valid UUID")
	}
	return nil
}

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
