package config

// Feature flags gate IAMKit's own features (not a flag service for
// applications). Deployment values come from IAMKIT_FEATURES
// ("name=true,other=false"); environment-scoped flags can be overridden per
// environment (environment_features). Effective value: environment
// override › deployment value › Default. Names removed from the registry
// are ignored wherever they are still stored.

// FeatureScope says where a flag may be set.
type FeatureScope string

const (
	// FeatureDeployment flags are set only by IAMKIT_FEATURES.
	FeatureDeployment FeatureScope = "deployment"
	// FeatureEnvironment flags may also be overridden per environment.
	FeatureEnvironment FeatureScope = "environment"
)

// Flag is one registered feature flag.
type Flag struct {
	Name        string
	Default     bool
	Scope       FeatureScope
	Description string
}

// Registered flag names.
const (
	// FeatureBetaLanguages offers the machine-drafted (beta) languages on
	// hosted pages and emails when the environment does not list its
	// languages; off leaves English and Spanish.
	FeatureBetaLanguages = "beta_languages"
	// FeatureSAMLIdP serves IAMKit as a SAML identity provider
	// (/saml/:environment/* and the SAML applications API).
	FeatureSAMLIdP = "saml_idp"
	// FeatureActions runs the environment's actions (hooks); off skips
	// every condition without calling its targets.
	FeatureActions = "actions"
)

// Flags is the registry, in display order.
var Flags = []Flag{
	{Name: FeatureBetaLanguages, Default: true, Scope: FeatureEnvironment, Description: "Offer machine-drafted (beta) languages on hosted pages and emails when the environment does not list its languages"},
	{Name: FeatureSAMLIdP, Default: true, Scope: FeatureDeployment, Description: "Serve IAMKit as a SAML 2.0 identity provider for applications"},
	{Name: FeatureActions, Default: true, Scope: FeatureEnvironment, Description: "Call the environment's actions (sign-in, token and request hooks)"},
}

// FindFlag returns the registered flag called name.
func FindFlag(name string) (Flag, bool) {
	for _, f := range Flags {
		if f.Name == name {
			return f, true
		}
	}
	return Flag{}, false
}
