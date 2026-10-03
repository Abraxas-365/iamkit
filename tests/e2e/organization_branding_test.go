package e2e_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// authorizeWith starts a hosted authorization with extra authorize
// parameters (scope replaces the default).
func (b *browser) authorizeWith(client string, extra url.Values) page {
	b.t.Helper()
	sum := sha256.Sum256([]byte(hostedVerifier))
	q := url.Values{"client_id": {client}, "redirect_uri": {"https://app.example/callback"}, "response_type": {"code"}, "scope": {"openid offline_access"}, "state": {"unpredictable-state-123456"}, "nonce": {"unpredictable-nonce-123456"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	for k, v := range extra {
		q[k] = v
	}
	return b.get("/oauth/authorize?" + q.Encode())
}

// TestOrganizationBranding: an organization's overrides lay over the client
// style and environment default (field by field) on its sign-in pages —
// known from the organization hint, the chooser or the verified email
// domain — on its invitation pages and emails; the hint also limits the
// sign-in to that organization. Operators and the organization's own
// administrators (iam:org:settings:write) manage the overrides.
func TestOrganizationBranding(t *testing.T) {
	smtp := newFakeSMTP(t)
	e := newEnv(t, loopbackMail(authmodule.Mail{}))
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "127.0.0.1", "smtp_port": smtp.Port}, 204)
	client := e.hostedClient()
	settings := e.Base + "/login-settings"
	orgStyle := settings + "/organizations/" + e.Org
	e.Must("PUT", settings, e.Owner, fiber.Map{"display_name": "Platform", "logo_url": "https://cdn.example/platform.png", "accent_color": "#112233"}, 200)

	// Operators: none yet (every field null), validated, scoped, audited.
	if s := e.Must("GET", orgStyle, e.Owner, nil, 200).JSON; s["display_name"] != nil || s["theme"] != nil || s["organization_id"] != e.Org {
		t.Fatalf("empty overrides = %v", s)
	}
	e.Must("PUT", orgStyle, e.Owner, fiber.Map{"accent_color": "red"}, 400)
	e.Must("PUT", orgStyle, e.Owner, fiber.Map{"logo_url": "http://cdn.example/a.png"}, 400)
	e.Must("PUT", settings+"/organizations/not-a-uuid", e.Owner, fiber.Map{}, 400)
	e.Must("PUT", settings+"/organizations/"+uuid.NewString(), e.Owner, fiber.Map{"display_name": "Ghost"}, 404)
	e.Must("DELETE", orgStyle, e.Owner, nil, 404)
	saved := e.Must("PUT", orgStyle, e.Owner, fiber.Map{"display_name": "Acme Corp", "accent_color": "#AA0000"}, 200).JSON
	if saved["display_name"] != "Acme Corp" || saved["accent_color"] != "#aa0000" || saved["logo_url"] != nil {
		t.Fatalf("saved = %v", saved)
	}
	if e.audited("PUT", "/management/v1/environments/"+e.EnvID+"/login-settings/organizations/"+e.Org) != 1 {
		t.Fatal("organization branding not audited")
	}

	// Without a known organization the page keeps the environment brand.
	if p := e.browser().authorize(client).Body; !strings.Contains(p, "<title>Sign in · Platform</title>") {
		t.Fatalf("no hint:\n%s", p)
	}
	// The hint (parameter or scope) brands it; the logo is inherited.
	for _, extra := range []url.Values{{"organization_id": {e.Org}}, {"scope": {"openid urn:iamkit:org:id:" + e.Org}}} {
		b := e.browser()
		start := b.authorizeWith(client, extra)
		if start.Status != 303 {
			t.Fatalf("hinted authorize %v: %d %s", extra, start.Status, start.Body)
		}
		p := b.get(start.Location).Body
		if !strings.Contains(p, "<title>Sign in · Acme Corp</title>") || !strings.Contains(p, "--accent:#aa0000") || !strings.Contains(p, "https://cdn.example/platform.png") {
			t.Fatalf("hinted page %v:\n%s", extra, p)
		}
	}
	// Malformed or conflicting hints are refused before any page.
	for _, extra := range []url.Values{{"organization_id": {"acme"}}, {"organization_id": {e.Org}, "scope": {"openid urn:iamkit:org:id:" + uuid.NewString()}}} {
		if p := e.browser().authorizeWith(client, extra); p.Status == 303 && strings.HasPrefix(p.Location, "/hosted/login") {
			t.Fatalf("bad hint %v accepted: %q", extra, p.Location)
		}
	}

	// A client style sits between: the organization wins only its fields.
	e.Must("PUT", settings+"/clients/"+client, e.Owner, fiber.Map{"display_name": "Billing", "logo_url": "https://cdn.example/billing.png"}, 200)
	b := e.browser()
	p := b.get(b.authorizeWith(client, url.Values{"organization_id": {e.Org}}).Location).Body
	if !strings.Contains(p, "· Acme Corp</title>") || !strings.Contains(p, "https://cdn.example/billing.png") {
		t.Fatalf("client ← organization merge:\n%s", p)
	}
	e.Must("DELETE", settings+"/clients/"+client, e.Owner, nil, 204)

	// The typed email's verified domain brands the password page.
	domain := e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains", e.Owner, fiber.Map{"domain": "acme.example"}, 201).JSON
	e.Must("POST", e.Base+"/organizations/"+e.Org+"/domains/"+domain["id"].(string)+"/force-verify", e.Owner, nil, 200)
	b = e.browser()
	tk := b.authorize(client).field("ticket")
	if pw := b.post("/hosted/login/identify", url.Values{"ticket": {tk}, "email": {"someone@acme.example"}}); !strings.Contains(pw.Body, "· Acme Corp</title>") {
		t.Fatalf("domain branding: %d %s", pw.Status, pw.Body)
	}

	// The hint limits the sign-in: Alice (Acme and Beta) skips the chooser
	// into the hinted organization; a hint she cannot enter fails.
	beta := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Beta"})
	e.Join(beta, e.Alice)
	e.Grant(beta, e.Alice, e.Res, "invoices:write")
	b = e.browser()
	tk = b.get(b.authorizeWith(client, url.Values{"organization_id": {beta}}).Location).field("ticket")
	tokens := b.exchange(client, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	if claims(t, tokens["access_token"].(string))["organization_id"] != beta {
		t.Fatal("hinted sign-in entered another organization")
	}
	gamma := e.ID("POST", e.Base+"/organizations", fiber.Map{"name": "Gamma"})
	b = e.browser()
	tk = b.get(b.authorizeWith(client, url.Values{"organization_id": {gamma}}).Location).field("ticket")
	if r := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}); r.Status < 400 {
		t.Fatalf("hint for a foreign organization: %d %s", r.Status, r.Body)
	}
	// Without a hint she chooses; the page answering the choice already
	// wears the chosen organization's brand (here: its required enrollment).
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": true}, 204)
	b = e.browser()
	tk = b.authorize(client).field("ticket")
	choose := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}})
	if len(choose.fields("organization_id")) != 2 || strings.Contains(choose.Body, "Acme Corp") {
		t.Fatalf("chooser: %d %s", choose.Status, choose.Body)
	}
	if enroll := b.post("/hosted/login/organization", url.Values{"ticket": {tk}, "organization_id": {e.Org}}); !strings.Contains(enroll.Body, "· Acme Corp</title>") || !strings.Contains(enroll.Body, "--accent:#aa0000") {
		t.Fatalf("page after the choice: %d %s", enroll.Status, enroll.Body)
	}
	e.Must("PATCH", e.Base+"/organizations/"+e.Org, e.Owner, fiber.Map{"mfa_required": false}, 204)

	// Invitations into the organization: page and email use its brand.
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "newbie@elsewhere.example"}, 201).JSON
	if p := e.browser().get("/hosted/invite?token=" + inv["token"].(string)); !strings.Contains(p.Body, "· Acme Corp</title>") {
		t.Fatalf("invite page:\n%s", p.Body)
	}
	if m := smtp.Last(); !strings.Contains(m.HTML, "Acme Corp") || !strings.Contains(m.HTML, "#aa0000") {
		t.Fatalf("invitation email not organization-branded:\n%s", m.HTML)
	}
	// Other organizations' invitations keep the environment brand.
	e.Must("POST", e.Base+"/organizations/"+beta+"/invitations", e.Owner, fiber.Map{"email": "other@elsewhere.example"}, 201)
	if m := smtp.Last(); strings.Contains(m.HTML, "Acme Corp") || !strings.Contains(m.HTML, "Platform") {
		t.Fatalf("other invitation:\n%s", m.HTML)
	}

	// Previews: saved (?organization=) and drafts over the default.
	saw := e.Must("GET", settings+"/preview?page=password&organization="+e.Org, e.Owner, nil, 200).JSON["html"].(string)
	if !strings.Contains(saw, "· Acme Corp</title>") {
		t.Fatalf("saved preview:\n%s", saw)
	}
	draft := e.Must("POST", settings+"/preview", e.Owner, fiber.Map{"organization": fiber.Map{"display_name": "Draft Org"}}, 200).JSON["html"].(string)
	if !strings.Contains(draft, "Draft Org") || !strings.Contains(draft, "https://cdn.example/platform.png") {
		t.Fatalf("draft preview:\n%s", draft)
	}
	e.Must("POST", settings+"/preview", e.Owner, fiber.Map{"organization": fiber.Map{"accent_color": "red"}}, 400)

	// The organization's own administrators, with iam:org:settings:write.
	e.Must("POST", e.Base+"/application-resources", e.Owner, fiber.Map{"application_id": e.Client, "resource_id": e.IAMResource()}, 201)
	olga := e.ID("POST", e.Base+"/users", fiber.Map{"name": "Olga", "email": "olga@example.com", "password": e.Pass, "home_organization_id": e.Org})
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": olga, "role_id": e.systemRole("org_viewer")}, 204)
	e.Must("POST", e.Base+"/role-assignments", e.Owner, fiber.Map{"organization_id": e.Org, "user_id": e.Alice, "role_id": e.systemRole("org_settings_manager")}, 204)
	admin := "/api/v1/environments/" + e.EnvID + "/organizations/" + e.Org + "/admin"
	viewer, manager := e.orgAdminToken(e.Org, "olga@example.com"), e.orgAdminToken(e.Org, e.AliceEmail)
	if s := e.Must("GET", admin+"/branding", viewer, nil, 200).JSON; s["display_name"] != "Acme Corp" {
		t.Fatalf("admin branding = %v", s)
	}
	e.Must("PUT", admin+"/branding", viewer, fiber.Map{"display_name": "Hijack"}, 403)
	e.Must("PUT", admin+"/branding", manager, fiber.Map{"display_name": "Acme Inc"}, 200)
	if e.Must("GET", orgStyle, e.Owner, nil, 200).JSON["display_name"] != "Acme Inc" {
		t.Fatal("admin change not saved")
	}
	e.Must("GET", "/api/v1/environments/"+e.EnvID+"/organizations/"+beta+"/admin/branding", manager, nil, 403)
	// Password policy: organization requirements only tighten.
	if pp := e.Must("GET", admin+"/password-policy", viewer, nil, 200).JSON; pp["custom"] != false {
		t.Fatalf("password policy = %v", pp)
	}
	e.Must("PUT", admin+"/password-policy", viewer, fiber.Map{"min_length": 16}, 403)
	if pp := e.Must("PUT", admin+"/password-policy", manager, fiber.Map{"min_length": 16}, 200).JSON; pp["min_length"].(float64) != 16 {
		t.Fatalf("set password policy = %v", pp)
	}
	if pp := e.Must("GET", e.Base+"/organizations/"+e.Org+"/password-policy", e.Owner, nil, 200).JSON; pp["min_length"].(float64) != 16 {
		t.Fatalf("operator view = %v", pp)
	}
	e.Must("DELETE", admin+"/password-policy", manager, nil, 204)
	e.Must("DELETE", admin+"/branding", manager, nil, 204)
	b = e.browser()
	if p := b.get(b.authorizeWith(client, url.Values{"organization_id": {e.Org}}).Location); p.Status != 200 || strings.Contains(p.Body, "Acme Inc") || !strings.Contains(p.Body, "· Platform</title>") {
		t.Fatalf("dropped overrides still shown: %d %s", p.Status, p.Body)
	}

	// A theme override is kept whole; deleting the organization drops it.
	e.Must("PUT", settings+"/organizations/"+gamma, e.Owner, fiber.Map{"display_name": "Gone", "theme": fiber.Map{"mode": "dark"}}, 200)
	if s := e.Must("GET", settings+"/organizations/"+gamma, e.Owner, nil, 200).JSON; s["theme"].(map[string]any)["mode"] != "dark" {
		t.Fatalf("theme override = %v", s)
	}
	if _, err := e.DB.Exec(`DELETE FROM organizations WHERE id=$1`, gamma); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := e.DB.Get(&n, `SELECT count(*) FROM organization_login_settings WHERE organization_id=$1`, gamma); err != nil || n != 0 {
		t.Fatalf("overrides of a deleted organization kept: %d %v", n, err)
	}
}
