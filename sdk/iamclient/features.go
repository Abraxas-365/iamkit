package iamclient

import (
	"context"
	"time"
)

// Feature is one of IAMKit's own feature flags in an environment: its
// registry default, the deployment value (IAMKIT_FEATURES, nil = unset),
// the environment's override (nil = none) and the effective value
// (environment › deployment › default). Scope is "environment" (may be
// overridden per environment) or "deployment" (IAMKIT_FEATURES only).
type Feature struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Scope       string     `json:"scope"`
	Default     bool       `json:"default"`
	Deployment  *bool      `json:"deployment"`
	Environment *bool      `json:"environment"`
	Enabled     bool       `json:"enabled"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

// Features lists the registered features and their state.
func (e Environment) Features(ctx context.Context) ([]Feature, error) {
	var out struct {
		Items []Feature `json:"items"`
	}
	err := e.operation(ctx, "GET", []string{"features"}, nil, &out)
	if out.Items == nil {
		out.Items = []Feature{}
	}
	return out.Items, err
}

// Feature returns one feature (404 UNKNOWN_FEATURE for unregistered names).
func (e Environment) Feature(ctx context.Context, name string) (Feature, error) {
	var out Feature
	err := e.operation(ctx, "GET", []string{"features", name}, nil, &out)
	return out, err
}

// SetFeature overrides an environment-scoped feature for the environment
// (deployment-scoped ones are refused). Audited as feature.updated.
func (e Environment) SetFeature(ctx context.Context, name string, enabled bool) (Feature, error) {
	var out Feature
	err := e.operation(ctx, "PUT", []string{"features", name}, map[string]bool{"enabled": enabled}, &out)
	return out, err
}

// ResetFeature removes the environment's override. Audited as
// feature.reset when one existed.
func (e Environment) ResetFeature(ctx context.Context, name string) (Feature, error) {
	var out Feature
	err := e.operation(ctx, "DELETE", []string{"features", name}, nil, &out)
	return out, err
}
