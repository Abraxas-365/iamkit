package identity

import "testing"

func TestPermissionBoundary(t *testing.T) {
	for _, p := range []string{"iam:*", "iam:users:write", "management:keys:write", "*", "invoice:*", " x", ""} {
		if ValidatePermissions([]string{p}) == nil {
			t.Errorf("accepted %q", p)
		}
	}
	if ValidatePermissions([]string{"invoices:read", "invoices:approve"}) != nil {
		t.Fatal("business permissions rejected")
	}
	if Subset([]string{"invoices:approve"}, []string{"invoices:read"}) {
		t.Fatal("expanded permissions")
	}
}
func TestEmailAndRedirects(t *testing.T) {
	if email, err := Email(" Alice@Example.com "); err != nil || email != "alice@example.com" {
		t.Fatal(email, err)
	}
	if _, err := Email("Alice <alice@example.com>"); err == nil {
		t.Fatal("display name accepted")
	}
	for _, u := range []string{"http://example.com/callback", "https://user:pass@example.com", "https://example.com/#fragment", "/callback"} {
		if ValidateRedirects([]string{u}) == nil {
			t.Error(u)
		}
	}
}
