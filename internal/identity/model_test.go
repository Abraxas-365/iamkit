package identity

import "testing"

func TestAvatarURL(t *testing.T) {
	for in, want := range map[string]string{"": "", "  ": "", " https://cdn.example/a.png ": "https://cdn.example/a.png"} {
		if got, err := AvatarURL(in); err != nil || got != want {
			t.Errorf("AvatarURL(%q) = %q, %v", in, got, err)
		}
	}
	long := "https://cdn.example/" + string(make([]byte, AvatarMaxLength))
	for _, bad := range []string{"http://cdn.example/a.png", "javascript:alert(1)", "data:image/png;base64,AA", "https://user:pw@cdn.example/a", "https:///a.png", "//cdn.example/a", long} {
		if _, err := AvatarURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestPhone(t *testing.T) {
	for in, want := range map[string]string{"+1 (415) 555-0100": "+14155550100", "+51.987.654.321": "+51987654321"} {
		if got, err := Phone(in); err != nil || got != want {
			t.Errorf("Phone(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "4155550100", "+0123456789", "+1", "+1234567890123456", "+1 415 555 01OO", "1+4155550100"} {
		if _, err := Phone(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

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
	for _, u := range []string{"http://example.com/callback", "http://localhost.example.com/cb", "http://10.0.0.1/cb", "https://user:pass@example.com", "https://example.com/#fragment", "http://localhost/#f", "/callback"} {
		if ValidateRedirects([]string{u}) == nil {
			t.Error(u)
		}
	}
	for _, u := range []string{"https://app.example.com/callback", "http://localhost:3000/callback", "http://127.0.0.1:8765/cb", "http://[::1]/cb", "http://LOCALHOST/cb"} {
		if err := ValidateRedirects([]string{u}); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"http://localhost/cb", "http://127.0.0.1/cb", "https://u:p@example.com", "/x"} {
		if ValidateHTTPS([]string{u}) == nil {
			t.Error("ValidateHTTPS accepted", u)
		}
	}
	if err := ValidateHTTPS([]string{"https://sp.example.com/acs"}); err != nil {
		t.Fatal(err)
	}
}

func TestUsername(t *testing.T) {
	for in, want := range map[string]string{"": "", " Ada.Lovelace ": "ada.lovelace", "a_1-b": "a_1-b", "007": "007"} {
		if got, err := Username(in); err != nil || got != want {
			t.Errorf("Username(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"ab", "ada@example.com", "_ada", ".ada", "ada lovelace", "ádá", string(make([]byte, UsernameMaxLength+1))} {
		if _, err := Username(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestLogin(t *testing.T) {
	if email, username, err := Login(" Ada@Example.com "); err != nil || email != "ada@example.com" || username != "" {
		t.Fatalf("email login = %q %q %v", email, username, err)
	}
	if email, username, err := Login("Ada"); err != nil || email != "" || username != "ada" {
		t.Fatalf("username login = %q %q %v", email, username, err)
	}
	for _, bad := range []string{"", "  ", "a@", "x"} {
		if _, _, err := Login(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
