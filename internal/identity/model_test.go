package identity

import "testing"

func TestPermissionBoundary(t *testing.T) {
	for _, p := range []string{"iam:*", "management:keys:write", "*", "invoice:*", " x", ""} {
		if ValidatePermissions([]string{p}, "") == nil {
			t.Errorf("accepted %q", p)
		}
	}
	if ValidatePermissions([]string{"invoices:read", "invoices:approve"}, "") != nil {
		t.Fatal("business permissions rejected")
	}
	if ValidatePermissions([]string{"iam:users:write", "iam:members:write"}, "") != nil {
		t.Fatal("iam permissions rejected")
	}
	if ValidatePermissions([]string{"iam:users:write"}, "iam") != nil {
		t.Fatal("valid iam-prefixed permission rejected")
	}
	// With prefix enforcement
	if ValidatePermissions([]string{"invoices:read"}, "invoices") != nil {
		t.Fatal("valid prefixed permission rejected")
	}
	if ValidatePermissions([]string{"billing:read"}, "invoices") == nil {
		t.Fatal("wrong prefix accepted")
	}
	if ValidatePrefix("invoices") != nil {
		t.Fatal("valid prefix rejected")
	}
	if ValidatePrefix("iam") != nil {
		t.Fatal("iam prefix rejected")
	}
	for _, bad := range []string{"", "Invoices", "management", "123", "a b"} {
		if ValidatePrefix(bad) == nil {
			t.Errorf("accepted bad prefix %q", bad)
		}
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
