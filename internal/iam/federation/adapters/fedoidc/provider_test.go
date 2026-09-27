package fedoidc

import (
	"net"
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

func TestPublicAddresses(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false,
		"169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false, "::1": false,
		"fe80::1": false, "fd00::1": false, "224.0.0.1": false, "::ffff:127.0.0.1": false,
	} {
		if got := Public(net.ParseIP(addr)); got != want {
			t.Errorf("Public(%s) = %v", addr, got)
		}
	}
}

func TestEmailVerifiedFlag(t *testing.T) {
	if flag(nil) != nil {
		t.Fatal("absent claim must stay absent")
	}
	for v, want := range map[any]bool{true: true, false: false, "true": true, "false": false, "garbage": false, 1.0: false} {
		if got := flag(v); got == nil || *got != want {
			t.Errorf("flag(%v) = %v", v, got)
		}
	}
}
