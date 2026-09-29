package fedldap

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedldap/ldaptest"
)

type plain struct{}

func (plain) Seal(b []byte) (string, error) { return string(b), nil }
func (plain) Open(s string) ([]byte, error) { return []byte(s), nil }

const base = "ou=people,dc=acme,dc=com"

func users() []ldaptest.Entry {
	return []ldaptest.Entry{
		{DN: "cn=svc,dc=acme,dc=com", Password: "svc-secret"},
		{DN: "uid=jane," + base, Password: "jane-pass", Attributes: map[string][]string{"mail": {"Jane@Acme.com"}, "uid": {"jane"}, "displayName": {"Jane Doe"}, "entryUUID": {"2f1c-uuid"}}},
		{DN: "uid=twin1," + base, Password: "x", Attributes: map[string][]string{"mail": {"twin@acme.com"}}},
		{DN: "uid=twin2," + base, Password: "x", Attributes: map[string][]string{"mail": {"twin@acme.com"}}},
		{DN: "uid=guid," + base, Password: "guid-pass", Attributes: map[string][]string{"userPrincipalName": {"guid@acme.com"}, "objectGUID": {"\x01\x02\xff"}, "cn": {"Guid"}}},
	}
}

func loopback() Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
}

func connection(s *ldaptest.Server) federation.Connection {
	return federation.Connection{Provider: federation.ProviderLDAP, Sealed: "svc-secret", Options: federation.Options{
		URL: s.URL, StartTLS: strings.HasPrefix(s.URL, "ldap://"), BindDN: "cn=svc,dc=acme,dc=com", UserBaseDN: base, CAPEM: s.CA,
	}}
}

func status(err error) int {
	var e *errx.Error
	if errx.As(err, &e) {
		return e.HTTPStatus
	}
	return 0
}

func TestAuthenticateLDAPS(t *testing.T) {
	s := ldaptest.Start(t, true, users()...)
	d := New(plain{}, nil, loopback())
	c := connection(s)
	claims, err := d.Authenticate(context.Background(), c, "jane@acme.com", "jane-pass")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "2f1c-uuid" || claims.Email != "jane@acme.com" || claims.Name != "Jane Doe" {
		t.Fatalf("claims %+v", claims)
	}
	if _, err = d.Authenticate(context.Background(), c, "jane@acme.com", "wrong"); status(err) != 401 {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err = d.Authenticate(context.Background(), c, "nobody@acme.com", "jane-pass"); status(err) != 401 {
		t.Fatalf("unknown user: %v", err)
	}
	if _, err = d.Authenticate(context.Background(), c, "twin@acme.com", "x"); status(err) != 401 {
		t.Fatalf("ambiguous filter must not bind: %v", err)
	}
	if _, err = d.Authenticate(context.Background(), c, "jane@acme.com", ""); status(err) != 401 {
		t.Fatalf("empty password is an unauthenticated bind: %v", err)
	}
	// Binary objectGUID becomes hex; userPrincipalName is an email.
	claims, err = d.Authenticate(context.Background(), c, "guid@acme.com", "guid-pass")
	if err != nil || claims.Subject != "0102ff" || claims.Email != "guid@acme.com" || claims.Name != "Guid" {
		t.Fatalf("guid claims %+v %v", claims, err)
	}
}

func TestAuthenticateFilterEscapesInput(t *testing.T) {
	s := ldaptest.Start(t, true, users()...)
	d := New(plain{}, nil, loopback())
	c := connection(s)
	// Without escaping, "*" would match every mail and "*)(uid=jane" would
	// rewrite the filter.
	for _, email := range []string{"*@acme.com", "jane@acme.com)(uid=*"} {
		if _, err := d.Authenticate(context.Background(), c, email, "jane-pass"); status(err) != 401 {
			t.Fatalf("%q: %v", email, err)
		}
	}
	c.Options.UserFilter = "(&(objectClass=*)(uid={username}))"
	if _, err := d.Authenticate(context.Background(), c, "jane@anything.example", "jane-pass"); status(err) != 401 {
		t.Fatalf("missing objectClass must not match: %v", err)
	}
	c.Options.UserFilter = "(uid={username})"
	claims, err := d.Authenticate(context.Background(), c, "jane@acme.com", "jane-pass")
	if err != nil || claims.Subject != "2f1c-uuid" {
		t.Fatalf("username filter: %+v %v", claims, err)
	}
	c.Options.Attributes = &federation.AttributeMapping{Subject: "uid", Name: "uid"}
	claims, err = d.Authenticate(context.Background(), c, "jane@acme.com", "jane-pass")
	if err != nil || claims.Subject != "jane" || claims.Name != "jane" {
		t.Fatalf("mapped attributes: %+v %v", claims, err)
	}
}

func TestAuthenticateStartTLS(t *testing.T) {
	s := ldaptest.Start(t, false, users()...)
	d := New(plain{}, nil, loopback())
	claims, err := d.Authenticate(context.Background(), connection(s), "jane@acme.com", "jane-pass")
	if err != nil || claims.Subject != "2f1c-uuid" {
		t.Fatalf("StartTLS: %+v %v", claims, err)
	}
}

func TestAuthenticateRefusesUntrustedCertificate(t *testing.T) {
	s := ldaptest.Start(t, true, users()...)
	d := New(plain{}, nil, loopback())
	c := connection(s)
	c.Options.CAPEM = ""
	if _, err := d.Authenticate(context.Background(), c, "jane@acme.com", "jane-pass"); status(err) != 502 {
		t.Fatalf("self-signed certificate without ca_pem: %v", err)
	}
	if len(s.Binds()) != 0 {
		t.Fatalf("no bind may cross an untrusted connection: %v", s.Binds())
	}
}

func TestAuthenticateServiceAccount(t *testing.T) {
	s := ldaptest.Start(t, true, users()...)
	d := New(plain{}, nil, loopback())
	c := connection(s)
	c.Sealed = "not-the-password"
	if _, err := d.Authenticate(context.Background(), c, "jane@acme.com", "jane-pass"); status(err) != 502 {
		t.Fatalf("wrong service password is the operator's problem, not the user's: %v", err)
	}
}

func TestGuardedDialRefusesPrivateHosts(t *testing.T) {
	s := ldaptest.Start(t, true, users()...)
	c := connection(s)
	if _, err := New(plain{}, nil, nil).Authenticate(context.Background(), c, "jane@acme.com", "jane-pass"); status(err) != 502 {
		t.Fatalf("loopback directory must be refused: %v", err)
	}
	if _, err := New(plain{}, []string{" LOCALHOST "}, nil).Authenticate(context.Background(), c, "jane@acme.com", "jane-pass"); err != nil {
		t.Fatalf("allowed host: %v", err)
	}
}

func TestText(t *testing.T) {
	if text([]byte{0x01, 0xff}) != "01ff" || text([]byte("abc")) != "abc" {
		t.Fatal("binary values are hex, printable ones stay")
	}
}
