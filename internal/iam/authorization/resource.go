package authorization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
)

type Resource struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Prefix      string   `json:"prefix"`
	Audience    string   `json:"audience"`
	Permissions []string `json:"permissions"`
}

// Validate checks the structural invariants Resource owns. Permission catalog
// and prefix format rules are enforced separately via identity helpers.
func (r Resource) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errx.Validation("resource name is required")
	}
	if strings.TrimSpace(r.Audience) == "" {
		return errx.Validation("resource audience is required")
	}
	if strings.TrimSpace(r.Prefix) == "" {
		return errx.Validation("resource prefix is required")
	}
	return nil
}

type Catalog struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// Validate checks the structural invariants Catalog owns.
func (c Catalog) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("catalog name is required")
	}
	return nil
}

type Mutation struct{ Environment, Actor, Action, Target string }
