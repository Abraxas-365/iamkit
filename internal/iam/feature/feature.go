// Package feature reads and overrides IAMKit's own feature flags
// (config.Flags): deployment values from IAMKIT_FEATURES, per-environment
// overrides for environment-scoped flags.
package feature

import (
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// Feature is a flag's state in one environment: its registry default, the
// deployment value (IAMKIT_FEATURES), the environment's override and the
// effective value (override › deployment › default).
type Feature struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Scope       config.FeatureScope `json:"scope"`
	Default     bool                `json:"default"`
	Deployment  *bool               `json:"deployment"`
	Environment *bool               `json:"environment"`
	Enabled     bool                `json:"enabled"`
	UpdatedAt   *time.Time          `json:"updated_at,omitempty"`
}

// Override is an environment's stored value of a flag.
type Override struct {
	Name      string
	Enabled   bool
	UpdatedAt time.Time
}

// Set overrides a flag for an environment.
type Set struct {
	Enabled *bool `json:"enabled"`
}

func (s Set) Validate() error {
	if s.Enabled == nil {
		return errx.Validation("enabled is required")
	}
	return nil
}

// Mutation is the audit context of an override change.
type Mutation struct {
	Environment identity.EnvironmentID
	Actor       string
	Action      string
	Target      string
}

// Deployment holds the deployment's flag values (IAMKIT_FEATURES).
type Deployment map[string]bool

// ParseDeployment reads IAMKIT_FEATURES: comma-separated name=bool pairs
// (a bare name means true). Names the registry does not know are returned
// apart, not applied: a flag removed in an upgrade must not stop a start.
func ParseDeployment(raw string) (Deployment, []string, error) {
	out, unknown := Deployment{}, []string(nil)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, value, found := strings.Cut(item, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		on := true
		if found {
			v, err := strconv.ParseBool(strings.TrimSpace(value))
			if err != nil {
				return nil, nil, errx.Validation("IAMKIT_FEATURES: " + name + " must be true or false")
			}
			on = v
		}
		if _, ok := config.FindFlag(name); !ok {
			unknown = append(unknown, name)
			continue
		}
		out[name] = on
	}
	return out, unknown, nil
}

// Flag returns the registered flag called name (404 otherwise).
func Flag(name string) (config.Flag, error) {
	flag, ok := config.FindFlag(name)
	if !ok {
		e := errx.NotFound("unknown feature " + strconv.Quote(name))
		e.Code = "UNKNOWN_FEATURE"
		return config.Flag{}, e
	}
	return flag, nil
}

// Settable refuses environment overrides of deployment-scoped flags.
func Settable(flag config.Flag) error {
	if flag.Scope != config.FeatureEnvironment {
		return errx.Validation("feature " + flag.Name + " is set for the whole deployment (IAMKIT_FEATURES)")
	}
	return nil
}

// Resolve is flag's state given the deployment values and, for an
// environment-scoped flag, the environment's override (nil: none).
func Resolve(flag config.Flag, deployment Deployment, override *Override) Feature {
	out := Feature{Name: flag.Name, Description: flag.Description, Scope: flag.Scope, Default: flag.Default, Enabled: flag.Default}
	if v, ok := deployment[flag.Name]; ok {
		out.Deployment, out.Enabled = &v, v
	}
	if override != nil && flag.Scope == config.FeatureEnvironment {
		v, at := override.Enabled, override.UpdatedAt
		out.Environment, out.Enabled, out.UpdatedAt = &v, v, &at
	}
	return out
}
