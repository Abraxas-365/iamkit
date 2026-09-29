package e2e_test

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/samlidp/adapters/samlxml/samltest"
	"github.com/gofiber/fiber/v2"
)

var postForm = regexp.MustCompile(`<form id="post" method="post" action="([^"]+)">`)

var postInput = regexp.MustCompile(`<input type="hidden" name="([A-Za-z]+)" value="([^"]*)">`)

// postField is a hidden field of the auto-submit page.
func postField(p page, name string) string {
	for _, m := range postInput.FindAllStringSubmatch(p.Body, -1) {
		if m[1] == name {
			return html.UnescapeString(m[2])
		}
	}
	return ""
}

// ssoPath is the request path of an absolute URL the SP sends the browser
// to (the harness serves the issuer https://iam.example in process).
func ssoPath(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Host != "iam.example" {
		t.Fatalf("SSO URL %q", raw)
	}
	return u.RequestURI()
}

// TestSAMLIdentityProvider covers IAMKit as a SAML 2.0 identity provider:
// an operator registers a service provider for an application/resource,
// the SP trusts the metadata, a user signs in through the ordinary hosted
// pages and the browser posts a signed response the SP verifies (email
// NameID, mapped attributes, SessionIndex = the IAMKit session); tickets
// are single use and bound to the browser, unregistered issuers and ACS
// URLs are refused, and the OAuth hosted flow is untouched.
func TestSAMLIdentityProvider(t *testing.T) {
	e := newEnv(t)
	sp := samltest.New("https://wiki.example.com/saml", "https://wiki.example.com/saml/acs")
	base := e.Base + "/saml/service-providers"

	// Management: validation, creation, listing, audit.
	e.Must("POST", base, e.Owner, fiber.Map{"name": "Wiki", "application_id": e.Client, "resource_id": e.Res, "entity_id": "https://wiki.example.com/saml", "acs_urls": []string{"http://wiki.example.com/acs"}}, 400)
	other := e.ID("POST", e.Base+"/resources", fiber.Map{"name": "Other", "prefix": "other", "audience": "https://other.example", "permissions": []string{"other:read"}})
	e.Must("POST", base, e.Owner, fiber.Map{"name": "Wiki", "application_id": e.Client, "resource_id": other, "entity_id": "https://wiki.example.com/saml", "acs_urls": []string{"https://wiki.example.com/saml/acs"}}, 409)
	created := e.Must("POST", base, e.Owner, fiber.Map{"name": "Wiki", "application_id": e.Client, "resource_id": e.Res, "entity_id": "https://wiki.example.com/saml", "acs_urls": []string{"https://wiki.example.com/saml/acs"}, "attributes": fiber.Map{"mail": "email", "displayName": "name", "roles": "permissions"}}, 201)
	id := created.JSON["id"].(string)
	if created.JSON["name_id_format"] != "email" || created.JSON["resource_name"] != "Billing" {
		t.Fatalf("created = %s", created.Body)
	}
	e.Must("POST", base, e.Owner, fiber.Map{"name": "Again", "application_id": e.Client, "resource_id": e.Res, "entity_id": "https://wiki.example.com/saml", "acs_urls": []string{"https://wiki.example.com/saml/acs"}}, 409)
	if list := items(e.Must("GET", base+"?application_id="+e.Client, e.Owner, nil, 200)); len(list) != 1 || list[0]["id"] != id {
		t.Fatalf("list = %v", list)
	}
	e.Must("GET", base+"/not-a-uuid", e.Owner, nil, 404)
	var audits int
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE action='saml_service_provider.create' AND target_id=$1`, id)
	if audits != 1 {
		t.Fatalf("create audits = %d", audits)
	}

	// The IdP settings the operator gives the SP, and its metadata.
	idp := e.Must("GET", e.Base+"/saml/identity-provider", e.Owner, nil, 200).JSON
	if idp["entity_id"] != "https://iam.example/saml/"+e.EnvID+"/metadata" || idp["sso_url"] != "https://iam.example/saml/"+e.EnvID+"/sso" || !strings.Contains(idp["certificate"].(string), "BEGIN CERTIFICATE") {
		t.Fatalf("identity provider = %v", idp)
	}
	b := e.browser()
	metadata := b.get(ssoPath(t, idp["entity_id"].(string)))
	if metadata.Status != 200 || metadata.Header.Get("Content-Type") != "application/samlmetadata+xml" || !strings.Contains(metadata.Body, "IDPSSODescriptor") {
		t.Fatalf("metadata: %d %s", metadata.Status, metadata.Body)
	}
	if p := b.get("/saml/" + e.Org + "/metadata"); p.Status != 404 {
		t.Fatalf("metadata of an unknown environment: %d", p.Status)
	}
	if err := sp.Trust([]byte(metadata.Body)); err != nil {
		t.Fatal(err)
	}

	// SP-initiated sign-in (HTTP-Redirect) through the hosted pages.
	redirect, requestID, err := sp.Redirect("relay-123")
	if err != nil {
		t.Fatal(err)
	}
	start := b.get(ssoPath(t, redirect))
	if start.Status != 303 || !strings.HasPrefix(start.Location, "/hosted/login?ticket=ik_samlreq_") {
		t.Fatalf("sso: %d %q %s", start.Status, start.Location, start.Body)
	}
	login := b.get(start.Location)
	tk := login.field("ticket")
	if login.Status != 200 || !strings.HasPrefix(tk, "ik_samlreq_") {
		t.Fatalf("hosted login: %d %s", login.Status, login.Body)
	}
	if p := e.browser().get(start.Location); p.Status != 401 {
		t.Fatalf("ticket without its browser: %d", p.Status)
	}
	b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	done := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	match := postForm.FindStringSubmatch(done.Body)
	if done.Status != 200 || match == nil || match[1] != "https://wiki.example.com/saml/acs" || postField(done, "RelayState") != "relay-123" {
		t.Fatalf("finish: %d %s", done.Status, done.Body)
	}
	csp := done.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe-inline") || strings.Count(done.Body, "<script") != strings.Count(done.Body, "<script nonce=") {
		t.Fatalf("post page CSP = %q", csp)
	}
	result, err := sp.Verify(postField(done, "SAMLResponse"), requestID)
	if err != nil {
		t.Fatalf("SP refused the response: %v", err)
	}
	if result.NameID != e.AliceEmail || result.Attributes["mail"][0] != e.AliceEmail || result.Attributes["displayName"][0] != "Alice" || !equal(result.Attributes["roles"], []string{"invoices:read"}) {
		t.Fatalf("assertion = %+v", result)
	}
	var session struct {
		User     string `db:"user_id"`
		Resource string `db:"resource_id"`
	}
	if err := e.DB.Get(&session, `SELECT user_id, resource_id FROM sessions WHERE id=$1`, result.SessionIndex); err != nil || session.User != e.Alice || session.Resource != e.Res {
		t.Fatalf("session %s: %+v %v", result.SessionIndex, session, err)
	}
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE action='saml.assertion_issued' AND actor_id=$1 AND target_id=$2`, e.Alice, id)
	if audits != 1 {
		t.Fatalf("assertion audits = %d", audits)
	}
	// The ticket is spent.
	if p := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); p.Status == 200 && postForm.MatchString(p.Body) {
		t.Fatal("ticket answered twice")
	}

	// HTTP-POST binding, persistent NameID, no attributes.
	e.Must("PATCH", base+"/"+id, e.Owner, fiber.Map{"name_id_format": "persistent", "attributes": fiber.Map{}}, 200)
	form, requestID, err := sp.Post()
	if err != nil {
		t.Fatal(err)
	}
	b = e.browser()
	start = b.post(ssoPath(t, idp["sso_url"].(string)), url.Values{"SAMLRequest": {form}})
	if start.Status != 303 {
		t.Fatalf("post binding: %d %s", start.Status, start.Body)
	}
	tk = b.get(start.Location).field("ticket")
	b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {e.AliceEmail}})
	done = b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if result, err = sp.Verify(postField(done, "SAMLResponse"), requestID); err != nil || result.NameID != e.Alice || len(result.Attributes) != 0 || postField(done, "RelayState") != "" {
		t.Fatalf("persistent assertion = %+v %v", result, err)
	}

	// Unknown service providers and unregistered ACS URLs are refused.
	stranger := samltest.New("https://stranger.example.com", "https://wiki.example.com/saml/acs")
	stranger.Trust([]byte(metadata.Body))
	redirect, _, _ = stranger.Redirect("")
	if p := e.browser().get(ssoPath(t, redirect)); p.Status != 400 {
		t.Fatalf("unknown SP: %d %s", p.Status, p.Body)
	}
	elsewhere := samltest.New("https://wiki.example.com/saml", "https://evil.example.com/acs")
	elsewhere.Trust([]byte(metadata.Body))
	redirect, _, _ = elsewhere.Redirect("")
	if p := e.browser().get(ssoPath(t, redirect)); p.Status != 400 {
		t.Fatalf("unregistered ACS: %d %s", p.Status, p.Body)
	}
	if p := e.browser().get("/saml/" + e.EnvID + "/sso?SAMLRequest=garbage"); p.Status != 400 {
		t.Fatalf("garbage request: %d", p.Status)
	}

	// Viewers read, only writers change; the resource link is held while
	// the provider exists.
	e.Must("DELETE", e.Base+"/application-resources/"+e.Client+"/"+e.Res, e.Owner, nil, 409)
	e.Must("DELETE", base+"/"+id, e.Owner, nil, 204)
	e.Must("GET", base+"/"+id, e.Owner, nil, 404)
	e.DB.Get(&audits, `SELECT count(*) FROM audit_events WHERE action='saml_service_provider.delete' AND target_id=$1`, id)
	if audits != 1 {
		t.Fatalf("delete audits = %d", audits)
	}
	redirect, _, _ = sp.Redirect("")
	if p := e.browser().get(ssoPath(t, redirect)); p.Status != 400 {
		t.Fatalf("deleted SP: %d", p.Status)
	}
}
