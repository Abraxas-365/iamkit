package fedsaml_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml"
	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/crewjam/saml"
)

var logoutUser = samltest.User{NameID: "u-42", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "ada@example.com", SessionIndex: "idx-7"}

// sloSetup is a connection with single logout whose identity provider
// publishes the given SingleLogoutService bindings.
func sloSetup(t *testing.T, bindings string) (fedsaml.Provider, *samltest.IdP, federation.Connection) {
	t.Helper()
	return setupSLO(t, federation.Options{SingleLogout: true}, bindings)
}

// trust makes idp know the service provider of c (its metadata, with the
// signing certificate and SLO endpoints).
func trust(t *testing.T, p fedsaml.Provider, idp *samltest.IdP, c federation.Connection) error {
	t.Helper()
	metadata, err := p.Metadata(context.Background(), c)
	if err != nil {
		return err
	}
	return idp.Trust(metadata)
}

func sloOf(c federation.Connection) string {
	return federation.SAMLServiceProvider(issuer, c.Environment, c.ID).SLO
}

func TestClaimsCarryLogoutIdentifiers(t *testing.T) {
	p, idp, c := sloSetup(t, "redirect")
	form := login(t, p, idp, c, "n", logoutUser)
	claims, err := p.Verify(context.Background(), c, form.SAMLResponse, "n", "")
	if err != nil || claims.NameID != "u-42" || claims.NameIDFormat != string(saml.PersistentNameIDFormat) || claims.SessionIndex != "idx-7" {
		t.Fatalf("claims %+v %v", claims, err)
	}
	link := c.Link(claims)
	if !link.Valid() || link.NameID != "u-42" || link.SessionIndex != "idx-7" {
		t.Fatalf("link %+v", link)
	}
}

func TestMetadataPublishesLogoutOnlyWithSingleLogout(t *testing.T) {
	p, _, c := sloSetup(t, "redirect")
	metadata, err := p.Metadata(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	text := string(metadata)
	if strings.Count(text, "SingleLogoutService") < 2 || !strings.Contains(text, sloOf(c)) || !strings.Contains(text, `use="signing"`) || !strings.Contains(text, `AuthnRequestsSigned="false"`) {
		t.Fatalf("metadata %s", text)
	}
	plain, _, off := setup(t, federation.Options{})
	metadata, _ = plain.Metadata(context.Background(), off)
	if strings.Contains(string(metadata), "SingleLogoutService") {
		t.Fatalf("metadata without single logout publishes it: %s", metadata)
	}
}

func TestPrepareRequiresLogoutService(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := samltest.New("https://idp.example.com")
	p := fedsaml.New(issuer, keyring{key}, nil)
	c := federation.Connection{ID: identity.NewConnectionID(), Environment: identity.NewEnvironmentID(), Organization: identity.NewOrganizationID(), Provider: federation.ProviderSAML, Options: federation.Options{MetadataXML: idp.Metadata(), SingleLogout: true}}
	if _, err := p.Prepare(context.Background(), c); err == nil || !strings.Contains(err.Error(), "SingleLogoutService") {
		t.Fatalf("prepare without a SingleLogoutService: %v", err)
	}
	idp.SLO = "post"
	c.Options.MetadataXML = idp.Metadata()
	c, err = p.Prepare(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	service, ok, err := p.LogoutService(c)
	if err != nil || !ok || service.Binding != federation.BindingPOST || service.Location != "https://idp.example.com/slo" {
		t.Fatalf("service %+v %v %v", service, ok, err)
	}
	idp.SLO = "both"
	c.Options.MetadataXML = idp.Metadata()
	if service, _, _ = p.LogoutService(c); service.Binding != federation.BindingRedirect {
		t.Fatalf("redirect is preferred: %+v", service)
	}
}

// message turns an identity provider message into what the SLO endpoint
// hands the provider.
func message(m samltest.Message, response bool) federation.LogoutMessage {
	out := federation.LogoutMessage{Redirect: !m.Post()}
	if m.Post() {
		if response {
			out.SAMLResponse = m.Field("SAMLResponse")
		} else {
			out.SAMLRequest = m.Field("SAMLRequest")
		}
		out.RelayState = m.Field("RelayState")
		return out
	}
	u, _ := url.Parse(m.URL)
	out.RawQuery = u.RawQuery
	q := u.Query()
	out.SAMLRequest, out.SAMLResponse, out.RelayState = q.Get("SAMLRequest"), q.Get("SAMLResponse"), q.Get("RelayState")
	return out
}

func TestVerifyLogoutRequest(t *testing.T) {
	p, idp, c := sloSetup(t, "both")
	ctx := context.Background()
	if err := trust(t, p, idp, c); err != nil {
		t.Fatal(err)
	}
	sp := federation.SAMLServiceProvider(issuer, c.Environment, c.ID).EntityID

	for _, post := range []bool{false, true} {
		name := map[bool]string{false: "redirect", true: "post"}[post]
		t.Run(name+" valid", func(t *testing.T) {
			m, err := idp.LogoutRequest(sp, logoutUser, post, "relay-1")
			if err != nil {
				t.Fatal(err)
			}
			req, err := p.VerifyLogoutRequest(ctx, c, message(m, false))
			if err != nil {
				t.Fatal(err)
			}
			if req.ID != m.RequestID || req.NameID != "u-42" || req.NameIDFormat != string(saml.PersistentNameIDFormat) || len(req.SessionIndexes) != 1 || req.SessionIndexes[0] != "idx-7" || req.Issuer != idp.EntityID() || req.RelayState != "relay-1" || !req.NotOnOrAfter.After(time.Now()) {
				t.Fatalf("request %+v", req)
			}
		})
		refused := map[string]samltest.Tamper{
			"unsigned":          {Unsigned: true},
			"other key":         {Other: samltest.New("https://idp.example.com")},
			"wrong destination": {Destination: "https://iam.example.com/elsewhere"},
			"wrong issuer":      {Issuer: "https://evil.example.com"},
			"expired":           {IssueInstant: time.Now().Add(-time.Hour)},
			"future":            {IssueInstant: time.Now().Add(time.Hour)},
		}
		for reason, tamper := range refused {
			t.Run(name+" "+reason, func(t *testing.T) {
				m, err := idp.LogoutRequest(sp, logoutUser, post, "", tamper)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = p.VerifyLogoutRequest(ctx, c, message(m, false)); err == nil {
					t.Fatal("accepted")
				}
			})
		}
	}

	t.Run("tampered redirect query", func(t *testing.T) {
		m, _ := idp.LogoutRequest(sp, logoutUser, false, "relay-1")
		lm := message(m, false)
		lm.RawQuery = strings.Replace(lm.RawQuery, "RelayState=relay-1", "RelayState=relay-2", 1)
		lm.RelayState = "relay-2"
		if _, err := p.VerifyLogoutRequest(ctx, c, lm); err == nil {
			t.Fatal("a query changed after signing was accepted")
		}
	})
	t.Run("signature stripped from query", func(t *testing.T) {
		m, _ := idp.LogoutRequest(sp, logoutUser, false, "")
		lm := message(m, false)
		lm.RawQuery = lm.RawQuery[:strings.Index(lm.RawQuery, "&Signature=")]
		if _, err := p.VerifyLogoutRequest(ctx, c, lm); err == nil {
			t.Fatal("an unsigned query was accepted")
		}
	})
	t.Run("repeated parameter", func(t *testing.T) {
		m, _ := idp.LogoutRequest(sp, logoutUser, false, "")
		lm := message(m, false)
		lm.RawQuery += "&SAMLRequest=AAAA"
		if _, err := p.VerifyLogoutRequest(ctx, c, lm); err == nil {
			t.Fatal("a repeated parameter was accepted")
		}
	})
	t.Run("no session index", func(t *testing.T) {
		m, _ := idp.LogoutRequest(sp, logoutUser, true, "", samltest.Tamper{NoSessionIndex: true})
		req, err := p.VerifyLogoutRequest(ctx, c, message(m, false))
		if err != nil || len(req.SessionIndexes) != 0 {
			t.Fatalf("%+v %v", req, err)
		}
	})
}

func TestLogoutResponseAnswersTheIdentityProvider(t *testing.T) {
	for _, bindings := range []string{"redirect", "post"} {
		t.Run(bindings, func(t *testing.T) {
			p, idp, c := sloSetup(t, bindings)
			ctx := context.Background()
			if err := trust(t, p, idp, c); err != nil {
				t.Fatal(err)
			}
			sp := federation.SAMLServiceProvider(issuer, c.Environment, c.ID).EntityID
			m, _ := idp.LogoutRequest(sp, logoutUser, bindings == "post", "relay-9")
			req, err := p.VerifyLogoutRequest(ctx, c, message(m, false))
			if err != nil {
				t.Fatal(err)
			}
			service, _, _ := p.LogoutService(c)
			for _, status := range []string{federation.StatusSuccess, federation.StatusPartialLogout} {
				out, err := p.LogoutResponse(ctx, c, service, req, status)
				if err != nil || out.Post() != (bindings == "post") || !strings.HasPrefix(out.URL, "https://idp.example.com/slo") {
					t.Fatalf("%+v %v", out, err)
				}
			}
		})
	}
}

func TestSPInitiatedLogout(t *testing.T) {
	for _, bindings := range []string{"redirect", "post"} {
		t.Run(bindings, func(t *testing.T) {
			p, idp, c := sloSetup(t, bindings)
			ctx := context.Background()
			if err := trust(t, p, idp, c); err != nil {
				t.Fatal(err)
			}
			service, ok, err := p.LogoutService(c)
			if err != nil || !ok {
				t.Fatal(err)
			}
			link := authentication.FederationLink{Connection: c.ID, NameID: "u-42", NameIDFormat: string(saml.PersistentNameIDFormat), SessionIndex: "idx-7"}
			out, id, err := p.LogoutRequest(ctx, c, service, link, "relay-3")
			if err != nil || id == "" || out.Post() != (bindings == "post") {
				t.Fatalf("%+v %q %v", out, id, err)
			}
			sp := federation.SAMLServiceProvider(issuer, c.Environment, c.ID).EntityID
			request := samltest.Message{URL: out.URL, Fields: out.Fields}
			got, response, err := idp.AnswerLogout(sp, request)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != id || got.NameID != "u-42" || got.SessionIndex != "idx-7" || got.RelayState != "relay-3" {
				t.Fatalf("the identity provider read %+v (request %s)", got, id)
			}

			lm := message(response, true)
			if inResponseTo, err := p.LogoutResponseID(lm); err != nil || inResponseTo != id {
				t.Fatalf("response id %q %v", inResponseTo, err)
			}
			if ok, err := p.VerifyLogoutResponse(ctx, c, lm, id); err != nil || !ok {
				t.Fatalf("response: %v %v", ok, err)
			}
			if _, err := p.VerifyLogoutResponse(ctx, c, lm, "another-request"); err == nil {
				t.Fatal("a response to another request was accepted")
			}
			other := samltest.New("https://idp.example.com")
			other.SLO = bindings
			_ = trust(t, p, other, c)
			_, forged, err := other.AnswerLogout(sp, request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.VerifyLogoutResponse(ctx, c, message(forged, true), id); err == nil {
				t.Fatal("a response signed by another key was accepted")
			}
		})
	}
}
