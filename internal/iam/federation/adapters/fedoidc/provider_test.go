package fedoidc

import (
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"testing"
)

func TestFederationCredentialBinding(t *testing.T) {
	t.Setenv("FEDERATION_CREDENTIAL_BINDINGS", `[{"environment_id":"production","issuer":"https://accounts.example","client_id":"client-a","secret_env":"IAMKIT_PROVIDER_A"}]`)
	approved := federation.Connection{Environment: "production", Issuer: "https://accounts.example", Client: "client-a", SecretEnv: "IAMKIT_PROVIDER_A"}
	if !(Provider{}).Approved(approved) {
		t.Fatal("approved tuple rejected")
	}
	for _, field := range []string{"environment", "issuer", "client", "secret"} {
		c := approved
		switch field {
		case "environment":
			c.Environment = "development"
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
