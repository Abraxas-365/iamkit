package fedoidc

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestFederationCredentialBinding(t *testing.T) {
	t.Setenv("FEDERATION_CREDENTIAL_BINDINGS", `[{"environment_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","issuer":"https://accounts.example","client_id":"client-a","secret_env":"IAMKIT_PROVIDER_A"}]`)
	prodEnv := identity.MustParseEnvironmentID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")
	devEnv := identity.MustParseEnvironmentID("aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff")
	approved := federation.Connection{Environment: prodEnv, Issuer: "https://accounts.example", Client: "client-a", SecretEnv: "IAMKIT_PROVIDER_A"}
	if !(Provider{}).Approved(approved) {
		t.Fatal("approved tuple rejected")
	}
	for _, field := range []string{"environment", "issuer", "client", "secret"} {
		c := approved
		switch field {
		case "environment":
			c.Environment = devEnv
		case "issuer":
			c.Issuer = "https://attacker.example"
		case "client":
			c.Client = "client-b"
		case "secret":
			c.SecretEnv = "IAMKIT_PROVIDER_B"
		}
		if (Provider{}).Approved(c) {
			t.Fatalf("credential crossed %s", field)
		}
	}
	t.Setenv("FEDERATION_CREDENTIAL_BINDINGS", "invalid")
	if (Provider{}).Approved(approved) {
		t.Fatal("malformed bindings accepted")
	}
}
