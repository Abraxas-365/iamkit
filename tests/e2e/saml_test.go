package e2e_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/federation/adapters/fedsaml/samltest"
	"github.com/crewjam/saml"
	"github.com/gofiber/fiber/v2"
)

// samlStart starts a headless SAML login and returns the IdP redirect and
// the binding cookie.
func (e *Env) samlStart(connection string) (string, *http.Cookie) {
	e.t.Helper()
	body, _ := json.Marshal(fiber.Map{"connection_id": connection, "environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res})
	req := httptest.NewRequest("POST", "/identity/v1/federation/start", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	var start map[string]any
	json.NewDecoder(res.Body).Decode(&start)
	res.Body.Close()
	if res.StatusCode != 200 {
		e.t.Fatalf("start: %d %v", res.StatusCode, start)
	}
	return start["authorization_url"].(string), res.Cookies()[0]
}

// acs posts a SAML response form and returns the 303 to the callback.
func (e *Env) acs(form samltest.Form) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/identity/v1/federation/saml/acs", strings.NewReader(url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {form.RelayState}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode, res.Header.Get("Location")
}

func (e *Env) follow(location string, cookie *http.Cookie) Response {
	e.t.Helper()
	req := httptest.NewRequest("GET", location, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := e.App.Test(req, 10000)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	out := Response{Status: res.StatusCode}
	raw, _ := io.ReadAll(res.Body)
	out.Body = string(raw)
	json.Unmarshal(raw, &out.JSON)
	return out
}

// samlLogin runs a full headless SAML login and returns the callback.
func (e *Env) samlLogin(idp *samltest.IdP, connection string, user samltest.User) (Response, samltest.Form) {
	e.t.Helper()
	redirect, cookie := e.samlStart(connection)
	form, err := idp.Answer(redirect, user)
	if err != nil {
		e.t.Fatal(err)
	}
	status, location := e.acs(form)
	if status != 303 || !strings.HasPrefix(location, "/identity/v1/federation/callback?code=ik_saml_") {
		e.t.Fatalf("acs: %d %q", status, location)
	}
	return e.follow(location, cookie), form
}

// TestSAMLConnection covers a SAML identity provider as an organization
// connection: metadata by XML and by URL, SP metadata, just-in-time
// provisioning, the binding cookie, replay and the hosted login.
func TestSAMLConnection(t *testing.T) {
	e := newEnv(t)
	idp := samltest.New("https://idp.example.com")
	connections := e.Base + "/federation-connections"

	// Creation rules.
	e.Must("POST", connections, e.Owner, fiber.Map{"name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata()}}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml"}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "client_secret": "x", "options": fiber.Map{"metadata_xml": idp.Metadata()}}, 400)
	e.Must("POST", connections, e.Owner, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": "<nope/>"}}, 400)
	conn := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Okta", "provider": "saml", "options": fiber.Map{"metadata_xml": idp.Metadata(), "name_id_format": "persistent"}})
	detail := e.Must("GET", connections+"/"+conn, e.Owner, nil, 200).JSON
	sp, _ := detail["saml"].(map[string]any)
	if detail["issuer"] != idp.EntityID() || sp == nil || sp["acs_url"] != "https://iam.example/identity/v1/federation/saml/acs" || sp["entity_id"] != detail["client_id"] || detail["callback_url"] != sp["acs_url"] {
		t.Fatalf("detail = %v", detail)
	}

	// Service provider metadata, public and cacheable.
	metadataPath := strings.TrimPrefix(sp["metadata_url"].(string), "https://iam.example")
	metadata := e.follow(metadataPath, nil)
	if metadata.Status != 200 || !strings.Contains(metadata.Body, `entityID="`+sp["entity_id"].(string)+`"`) || !strings.Contains(metadata.Body, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") {
		t.Fatalf("metadata: %d %s", metadata.Status, metadata.Body)
	}
	if again := e.follow(metadataPath, nil); certificateOf(again.Body) == "" || certificateOf(again.Body) != certificateOf(metadata.Body) {
		t.Fatal("SP certificate is not stable")
	}
	if r := e.follow("/identity/v1/federation/saml/"+e.EnvID+"/00000000-0000-4000-8000-000000000000/metadata", nil); r.Status != 404 {
		t.Fatalf("unknown metadata: %d", r.Status)
	}
	if err := idp.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}

	// JIT with a default group: the SAML user signs in with access.
	group := e.ID("POST", e.Base+"/organizations/"+e.Org+"/groups", fiber.Map{"name": "Everyone"})
	reader := e.ID("POST", e.Base+"/roles", fiber.Map{"name": "reader", "resource_id": e.Res, "permissions": []string{"invoices:read"}})
	e.Must("POST", e.Base+"/group-role-assignments", e.Owner, fiber.Map{"role_id": reader, "organization_id": e.Org, "group_id": group}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"jit_group_id": group}, 204)
	domain := e.ID("POST", e.Base+"/organizations/"+e.Org+"/domains", fiber.Map{"domain": "example.com"})
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain+"/force-verify", e.Owner, nil, 200)
	user := samltest.User{NameID: "00u-carol", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "carol@example.com", Name: "Carol"}
	carol, form := e.samlLogin(idp, conn, user)
	if carol.Status != 200 || !equal(e.permissions(carol.JSON["access_token"].(string)), []string{"invoices:read"}) {
		t.Fatalf("saml login: %d %s", carol.Status, carol.Body)
	}
	if amr := toString(claimsOf(t, carol.JSON["access_token"].(string))["amr"]); !strings.Contains(amr, `"fed"`) {
		t.Fatalf("amr = %s", amr)
	}
	var subject string
	if err := e.DB.Get(&subject, `SELECT x.subject FROM external_identities x JOIN users u ON u.id=x.user_id WHERE x.connection_id=$1 AND u.email='carol@example.com' AND u.email_verified AND x.origin='jit'`, conn); err != nil || subject != "00u-carol" {
		t.Fatalf("jit carol: %q %v", subject, err)
	}

	// Replay: the same response posted again for a new login is refused
	// (its InResponseTo names the first request; its ID was used).
	redirect, cookie := e.samlStart(conn)
	replayed := samltest.Form{SAMLResponse: form.SAMLResponse, RelayState: stateOf(t, redirect)}
	if status, location := e.acs(replayed); status != 303 {
		t.Fatalf("acs replay: %d", status)
	} else if r := e.follow(location, cookie); r.Status != 401 {
		t.Fatalf("replayed response: %d %s", r.Status, r.Body)
	}
	// The same assertion for its own login twice: the handle is single use.
	redirect, cookie = e.samlStart(conn)
	form, _ = idp.Answer(redirect, user)
	_, location := e.acs(form)
	if r := e.follow(location, cookie); r.Status != 200 {
		t.Fatalf("second login: %d %s", r.Status, r.Body)
	}
	if r := e.follow(location, cookie); r.Status != 401 {
		t.Fatalf("callback reused: %d", r.Status)
	}
	// Without the binding cookie the parked response cannot be used.
	redirect, _ = e.samlStart(conn)
	form, _ = idp.Answer(redirect, user)
	_, location = e.acs(form)
	if r := e.follow(location, nil); r.Status != 401 {
		t.Fatalf("callback without binding: %d", r.Status)
	}
	// Unknown RelayState, forged signature, foreign domain.
	if status, _ := e.acs(samltest.Form{SAMLResponse: form.SAMLResponse, RelayState: "ik_state_unknown"}); status != 401 {
		t.Fatalf("unknown relay state: %d", status)
	}
	forger := samltest.New("https://idp.example.com")
	_ = forger.Trust([]byte(metadata.Body))
	redirect, cookie = e.samlStart(conn)
	form, _ = forger.Answer(redirect, user)
	_, location = e.acs(form)
	if r := e.follow(location, cookie); r.Status != 401 {
		t.Fatalf("forged: %d %s", r.Status, r.Body)
	}
	if r, _ := e.samlLogin(idp, conn, samltest.User{NameID: "00u-dave", NameIDFormat: string(saml.PersistentNameIDFormat), Email: "dave@other.example"}); r.Status != 401 {
		t.Fatalf("foreign domain: %d %s", r.Status, r.Body)
	}

	// Metadata by URL, fetched through the federation transport; a later
	// metadata update may not switch the identity provider.
	published := idp.Metadata()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		io.WriteString(w, published)
	}))
	defer server.Close()
	e.IdP.Set(server.Client().Transport)
	byURL := e.ID("POST", connections, fiber.Map{"organization_id": e.Org, "name": "Okta URL", "provider": "saml", "options": fiber.Map{"metadata_url": server.URL + "/metadata"}})
	if d := e.Must("GET", connections+"/"+byURL, e.Owner, nil, 200).JSON; d["issuer"] != idp.EntityID() {
		t.Fatalf("by url = %v", d)
	}
	e.Must("PATCH", connections+"/"+byURL, e.Owner, fiber.Map{"options": fiber.Map{"metadata_xml": samltest.New("https://other-idp.example.com").Metadata()}}, 400)
	e.Must("PATCH", connections+"/"+byURL, e.Owner, fiber.Map{"options": fiber.Map{"metadata_url": server.URL + "/metadata", "sign_requests": true}}, 204)
	e.Must("PATCH", connections+"/"+byURL, e.Owner, fiber.Map{"client_secret": "x"}, 400)
	// Enabling fetches the metadata again; it must still name the same
	// identity provider.
	e.Must("DELETE", connections+"/"+byURL, e.Owner, nil, 204)
	published = samltest.New("https://other-idp.example.com").Metadata()
	e.Must("POST", connections+"/"+byURL+"/enable", e.Owner, nil, 400)
	published = idp.Metadata()
	e.Must("POST", connections+"/"+byURL+"/enable", e.Owner, nil, 204)

	// Hosted login: enforced SSO redirects to the IdP; the ACS resumes the
	// hosted journey in the browser that holds both cookies.
	client := e.hostedClient()
	e.Must("PATCH", connections+"/"+byURL, e.Owner, fiber.Map{"active": false}, 204)
	e.Must("PATCH", connections+"/"+conn, e.Owner, fiber.Map{"enforcement": "enforced"}, 204)
	b := e.browser()
	tk := b.authorize(client).field("ticket")
	sso := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {"carol@example.com"}})
	if sso.Status != 303 || !strings.HasPrefix(sso.Location, "https://idp.example.com/sso?SAMLRequest=") {
		t.Fatalf("enforced identify: %d %q %s", sso.Status, sso.Location, sso.Body)
	}
	form, err := idp.Answer(sso.Location, user)
	if err != nil {
		t.Fatal(err)
	}
	parked := b.post("/identity/v1/federation/saml/acs", url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {form.RelayState}})
	if parked.Status != 303 {
		t.Fatalf("hosted acs: %d %s", parked.Status, parked.Body)
	}
	tokens := b.exchange(client, b.get(parked.Location))
	if claims(t, tokens["access_token"].(string))["organization_id"] != e.Org {
		t.Fatal("SAML must sign in to its organization")
	}
}

func stateOf(t *testing.T, redirect string) string {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("RelayState")
}

func certificateOf(metadata string) string {
	_, rest, _ := strings.Cut(metadata, "X509Certificate>")
	cert, _, _ := strings.Cut(rest, "<")
	return cert
}

func toString(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
