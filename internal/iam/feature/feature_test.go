package feature_test

import (
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/feature"
)

func TestParseDeployment(t *testing.T) {
	got, unknown, err := feature.ParseDeployment(" beta_languages=false, SAML_IDP ,removed_flag=true,")
	if err != nil {
		t.Fatal(err)
	}
	if got[config.FeatureBetaLanguages] || !got[config.FeatureSAMLIdP] || len(got) != 2 {
		t.Fatalf("deployment = %v", got)
	}
	if len(unknown) != 1 || unknown[0] != "removed_flag" {
		t.Fatalf("unknown = %v", unknown)
	}
	if _, _, err := feature.ParseDeployment("saml_idp=maybe"); err == nil {
		t.Fatal("non-boolean value accepted")
	}
	if got, _, err := feature.ParseDeployment(""); err != nil || len(got) != 0 {
		t.Fatalf("empty = %v %v", got, err)
	}
}

func TestResolve(t *testing.T) {
	env := config.Flag{Name: "x", Default: true, Scope: config.FeatureEnvironment}
	if f := feature.Resolve(env, nil, nil); !f.Enabled || f.Deployment != nil || f.Environment != nil {
		t.Fatalf("default = %+v", f)
	}
	off := feature.Deployment{"x": false}
	if f := feature.Resolve(env, off, nil); f.Enabled || f.Deployment == nil {
		t.Fatalf("deployment = %+v", f)
	}
	at := time.Now()
	if f := feature.Resolve(env, off, &feature.Override{Name: "x", Enabled: true, UpdatedAt: at}); !f.Enabled || f.Environment == nil || !*f.Environment || f.UpdatedAt == nil {
		t.Fatalf("override = %+v", f)
	}
	deployment := config.Flag{Name: "x", Default: true, Scope: config.FeatureDeployment}
	if f := feature.Resolve(deployment, off, &feature.Override{Name: "x", Enabled: true}); f.Enabled || f.Environment != nil {
		t.Fatalf("deployment-scoped override applied: %+v", f)
	}
	if feature.Settable(deployment) == nil || feature.Settable(env) != nil {
		t.Fatal("Settable")
	}
}

func TestRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range config.Flags {
		if seen[f.Name] || f.Description == "" || (f.Scope != config.FeatureDeployment && f.Scope != config.FeatureEnvironment) {
			t.Fatalf("flag %+v", f)
		}
		seen[f.Name] = true
	}
	if _, err := feature.Flag("nope"); err == nil {
		t.Fatal("unknown flag found")
	}
}
