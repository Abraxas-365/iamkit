package organization

import (
	"context"
	"encoding/json"
)

type Boundary struct{ Environment, Organization string }
type Unit struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	Parent *string `json:"parent_id"`
}
type Profile struct {
	Unit    *string `json:"org_unit_id"`
	Manager *string `json:"manager_id"`
}
type Position struct {
	Name string `json:"name"`
	Code string `json:"code"`
}
type Assignment struct {
	Position string  `json:"position_id"`
	User     string  `json:"user_id"`
	Unit     *string `json:"org_unit_id"`
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

type StructureCommands interface {
	Check(context.Context, Boundary) error
	SaveUnit(context.Context, Boundary, Mutation, string, Unit) (string, error)
	DeleteUnit(context.Context, Boundary, Mutation, string) error
	SetProfile(context.Context, Boundary, Mutation, string, Profile) error
	SavePosition(context.Context, Boundary, Mutation, string, Position) (string, error)
	DeletePosition(context.Context, Boundary, Mutation, string) error
	AssignPosition(context.Context, Boundary, Assignment) (string, error)
	DeleteAssignment(context.Context, Boundary, Mutation, string) error
}
type StructureQueries interface {
	View(context.Context, Boundary, StructureView, string) (json.RawMessage, error)
}

type StructureRepository interface {
	Exists(context.Context, Boundary) (bool, error)
	View(context.Context, Boundary, StructureView, string) (json.RawMessage, error)
	SaveUnit(context.Context, Boundary, Mutation, string, Unit, bool) error
	DeleteUnit(context.Context, Boundary, Mutation, string) error
	SetProfile(context.Context, Boundary, Mutation, string, Profile) error
	CreatePosition(context.Context, Boundary, string, Position) error
	UpdatePosition(context.Context, Boundary, Mutation, string, Position) error
	DeletePosition(context.Context, Boundary, Mutation, string) error
	AssignPosition(context.Context, Boundary, string, Assignment) error
	DeleteAssignment(context.Context, Boundary, Mutation, string) error
}
