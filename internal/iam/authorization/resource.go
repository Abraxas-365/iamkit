package authorization

import (
	"strings"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type Resource struct {
	ID          identity.ResourceID `json:"id"`
	Name        string              `json:"name"`
	Prefix      string              `json:"prefix"`
	Audience    string              `json:"audience"`
	Permissions []string            `json:"permissions"`
}

// Validate checks the structural invariants Resource owns.
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

func (c Catalog) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return errx.Validation("catalog name is required")
	}
	return nil
}

type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}
