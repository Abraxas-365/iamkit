package oauth

import (
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
)

func TestValidateInitiateLoginURI(t *testing.T) {
	for _, ok := range []string{"", "https://app.example/login", "https://app.example/login?tenant=a", "http://localhost:3000/login", "http://127.0.0.1/login", "http://[::1]:8080/x"} {
		if err := ValidateInitiateLoginURI(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://app.example/login", "/login", "app.example/login", "https://user:pw@app.example/login", "https://app.example/login#frag", "javascript:alert(1)", "https://app.example/" + strings.Repeat("a", MaxInitiateLoginURI)} {
		if err := ValidateInitiateLoginURI(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestInitiateLoginTarget(t *testing.T) {
	to, err := InitiateLoginTarget("https://app.example/login?tenant=acme&iss=old", url.Values{"iss": {"https://iam.example"}, "connection_id": {"c1"}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(to)
	if u.Path != "/login" || u.Query().Get("tenant") != "acme" || u.Query().Get("iss") != "https://iam.example" || u.Query().Get("connection_id") != "c1" {
		t.Fatalf("target = %s", to)
	}
	if _, err := InitiateLoginTarget("/relative", nil); err == nil {
		t.Error("relative endpoint accepted")
	}
}

func TestConnectionHint(t *testing.T) {
	conn := identity.NewConnectionID()
	if id, err := ConnectionHint(url.Values{}); err != nil || !id.IsZero() {
		t.Fatalf("none: %v %v", id, err)
	}
	if id, err := ConnectionHint(url.Values{"connection_id": {conn.String()}}); err != nil || id != conn {
		t.Fatalf("valid: %v %v", id, err)
	}
	if _, err := ConnectionHint(url.Values{"connection_id": {"nope"}}); err == nil {
		t.Fatal("malformed accepted")
	}
	if FormConnection("state=x&connection_id="+conn.String()) != conn || !FormConnection("connection_id=nope").IsZero() || !FormConnection("%zz").IsZero() {
		t.Fatal("FormConnection")
	}
}
