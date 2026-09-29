package oauth

import (
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestAccessTokenFormat(t *testing.T) {
	base := Registration{Application: identity.NewApplicationID(), Resource: identity.NewResourceID(), Redirects: []string{"https://app.example/cb"}}
	for format, ok := range map[string]bool{"": true, "jwt": true, "opaque": true, "JWT": false, "reference": false} {
		input := base
		input.AccessTokenFormat = format
		if err := input.Validate(); (err == nil) != ok {
			t.Fatalf("registration format %q: %v", format, err)
		}
	}
	opaque, bad := "opaque", "paseto"
	if err := (ClientUpdate{AccessTokenFormat: &opaque}).Validate(); err != nil {
		t.Fatalf("update to opaque: %v", err)
	}
	if err := (ClientUpdate{AccessTokenFormat: &bad}).Validate(); err == nil {
		t.Fatal("update accepted an unknown format")
	}
}
