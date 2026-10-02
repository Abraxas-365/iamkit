package iamclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTypedAdministration(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Header.Get("X-API-Key") != "ik_mgmt_test" {
			t.Error("missing key")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			json.NewEncoder(w).Encode(User{ID: "user-1"})
		} else {
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "ik_mgmt_test")
	env := c.Environment("env-1")
	ctx := context.Background()
	user, err := env.User(ctx, "user-1")
	if err != nil || user.ID != "user-1" {
		t.Fatalf("user: %v %v", user, err)
	}
	if err = env.SetMemberProfile(ctx, "org-1", "user-1", MemberProfile{}); err != nil {
		t.Fatal(err)
	}
	if err = env.DeleteRole(ctx, "../roles"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	if len(paths) != 2 || paths[1] != "PUT /management/v1/environments/env-1/organizations/org-1/members/user-1/profile" {
		t.Fatalf("routes %v", paths)
	}
}

func TestEnvironmentMissingEndpoints(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "ik_mgmt_test")
	env := c.Environment("env-1")
	ctx := context.Background()

	// Test previously missing endpoints
	env.UnbindResource(ctx, "app-1", "res-1")
	env.ApplicationResources(ctx, "app-1")
	env.FederationConnections(ctx)
	env.FederationConnection(ctx, "conn-1")
	env.FederationIdentities(ctx, "conn-1")
	env.UnlinkExternalIdentity(ctx, "conn-1", "user-1")
	env.ProvisioningCredentials(ctx)
	env.OAuthClients(ctx)
	env.UpdateOAuthClient(ctx, "client-1", OAuthClientPatch{})
	env.LoginSettings(ctx)
	env.SetLoginSettings(ctx, LoginSettings{})
	env.ClientLoginStyles(ctx)
	env.ClientLoginSettings(ctx, "client-1")
	env.SetClientLoginSettings(ctx, "client-1", LoginSettings{})
	env.DeleteClientLoginSettings(ctx, "client-1")
	env.ClientSignIns(ctx)
	env.ClientSignIn(ctx, "client-1")
	env.SetClientSignIn(ctx, "client-1", SignIn{Password: true})
	env.DeleteClientSignIn(ctx, "client-1")
	env.RoleAssignments(ctx)
	env.Grant(ctx, "grant-1")
	env.DeleteGrant(ctx, "grant-1")
	env.UnassignRole(ctx, RoleAssignment{RoleID: "r1", OrganizationID: "o1", UserID: "u1"})

	expected := []string{
		"DELETE /management/v1/environments/env-1/application-resources/app-1/res-1",
		"GET /management/v1/environments/env-1/applications/app-1/resources",
		"GET /management/v1/environments/env-1/federation-connections",
		"GET /management/v1/environments/env-1/federation-connections/conn-1",
		"GET /management/v1/environments/env-1/federation-connections/conn-1/identities",
		"DELETE /management/v1/environments/env-1/external-identities/conn-1/user-1",
		"GET /management/v1/environments/env-1/provisioning-credentials",
		"GET /management/v1/environments/env-1/oauth-clients",
		"PATCH /management/v1/environments/env-1/oauth-clients/client-1",
		"GET /management/v1/environments/env-1/login-settings",
		"PUT /management/v1/environments/env-1/login-settings",
		"GET /management/v1/environments/env-1/login-settings/clients",
		"GET /management/v1/environments/env-1/login-settings/clients/client-1",
		"PUT /management/v1/environments/env-1/login-settings/clients/client-1",
		"DELETE /management/v1/environments/env-1/login-settings/clients/client-1",
		"GET /management/v1/environments/env-1/login-settings/sign-in",
		"GET /management/v1/environments/env-1/login-settings/clients/client-1/sign-in",
		"PUT /management/v1/environments/env-1/login-settings/clients/client-1/sign-in",
		"DELETE /management/v1/environments/env-1/login-settings/clients/client-1/sign-in",
		"GET /management/v1/environments/env-1/role-assignments",
		"GET /management/v1/environments/env-1/grants/grant-1",
		"DELETE /management/v1/environments/env-1/grants/grant-1",
		"DELETE /management/v1/environments/env-1/role-assignments/r1/o1/u1",
	}
	if len(paths) != len(expected) {
		t.Fatalf("paths count %d != %d: %v", len(paths), len(expected), paths)
	}
	for i, p := range expected {
		if paths[i] != p {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], p)
		}
	}
}

func TestOrganizationSSOEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	secret, bypass, group := "s", true, ""
	env.OrganizationFederations(ctx, "org-1")
	env.UpdateFederation(ctx, "conn-1", FederationPatch{ClientSecret: &secret, JITGroupID: &group})
	env.AddDomain(ctx, "org-1", "acme.example")
	env.Domains(ctx, "org-1")
	env.VerifyDomain(ctx, "org-1", "d-1")
	env.ForceVerifyDomain(ctx, "org-1", "d-1")
	env.DeleteDomain(ctx, "org-1", "d-1")
	env.UpdateMember(ctx, "org-1", "user-1", MemberPatch{SSOBypass: &bypass})
	if _, err := env.OrganizationFederations(ctx, "../x"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/management/v1/environments/env-1"
	expected := []string{
		"GET " + base + "/federation-connections",
		"PATCH " + base + "/federation-connections/conn-1",
		"POST " + base + "/organizations/org-1/domains",
		"GET " + base + "/organizations/org-1/domains",
		"POST " + base + "/organizations/org-1/domains/d-1/verify",
		"POST " + base + "/organizations/org-1/domains/d-1/force-verify",
		"DELETE " + base + "/organizations/org-1/domains/d-1",
		"PATCH " + base + "/organizations/org-1/members/user-1",
	}
	if len(calls) != len(expected) {
		t.Fatalf("calls %v", calls)
	}
	for i, want := range expected {
		if calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, calls[i], want)
		}
	}
}

func TestInvitationEndpoints(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" && r.URL.Path == "/management/v1/environments/env-1/organizations/org-1/invitations" {
			w.Write([]byte(`{"items":[{"id":"i-1","status":"pending"},{"id":"i-2","status":"accepted"}],"page":{"total":2}}`))
			return
		}
		w.Write([]byte(`{"id":"i-1","token":"ik_inv_x","delivery":"sent"}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	issued, err := env.Invite(ctx, "org-1", InvitationInput{Email: "bob@example.com"})
	if err != nil || issued.Token != "ik_inv_x" || issued.ID != "i-1" || issued.Delivery != "sent" {
		t.Fatalf("invite = %+v %v", issued, err)
	}
	if pending, err := env.Invitations(ctx, "org-1", "pending"); err != nil || len(pending) != 1 || pending[0].ID != "i-1" {
		t.Fatalf("pending = %+v %v", pending, err)
	}
	env.Invitation(ctx, "org-1", "i-1")
	env.ResendInvitation(ctx, "org-1", "i-1")
	env.RevokeInvitation(ctx, "org-1", "i-1")
	if _, err := env.Invite(ctx, "../x", InvitationInput{}); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/management/v1/environments/env-1/organizations/org-1/invitations"
	expected := []string{"POST " + base, "GET " + base, "GET " + base + "/i-1", "POST " + base + "/i-1/resend", "DELETE " + base + "/i-1"}
	if len(calls) != len(expected) {
		t.Fatalf("calls %v", calls)
	}
	for i, want := range expected {
		if calls[i] != want {
			t.Errorf("call[%d] = %q, want %q", i, calls[i], want)
		}
	}
}

func TestDeliveryEndpoints(t *testing.T) {
	var calls, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, strings.TrimSpace(string(b)))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/management/v1/environments/env-1/delivery":
			w.Write([]byte(`{"provider":"smtp","smtp_host":"smtp.acme.io","smtp_port":587,"has_secret":true}`))
		case "/management/v1/environments/env-1/delivery/templates", "/management/v1/environments/env-1/login-settings/locales":
			w.Write([]byte(`{"items":[{"purpose":"login","locale":"es","customized":true,"code":"es","name":"Español"}]}`))
		case "/management/v1/environments/env-1/delivery/preview":
			w.Write([]byte(`{"subject":"Tu código","html":"<p>","text":"123456"}`))
		default:
			w.Write([]byte(`{"purpose":"login","locale":"es","template":{"subject":"Hola"},"placeholders":["code"]}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()

	err := env.SetDeliveryConfig(ctx, SetDeliveryConfig{Provider: DeliverySMTP, FromEmail: "no-reply@acme.io", SMTPHost: "smtp.acme.io", SMTPPort: 587, SMTPUsername: "mailer", SMTPTLS: "starttls"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err := env.DeliveryConfig(ctx); err != nil || cfg.Provider != DeliverySMTP || cfg.SMTPHost != "smtp.acme.io" || !cfg.HasSecret {
		t.Fatalf("config = %+v %v", cfg, err)
	}
	// Webhook input without the new fields keeps the old wire shape.
	env.SetDeliveryConfig(ctx, SetDeliveryConfig{WebhookURL: "https://mail.example/hook", WebhookToken: "tok"})
	p, err := env.PreviewDelivery(ctx, DeliveryPreview{Purpose: EmailLogin, Locale: "es", Template: &EmailCopy{Subject: "Hola"}})
	if err != nil || p.Subject != "Tu código" || p.Text != "123456" {
		t.Fatalf("preview = %+v %v", p, err)
	}
	// Without a draft the preview is a read.
	env.PreviewDelivery(ctx, DeliveryPreview{Purpose: EmailInvitation, Locale: "es"})
	if items, err := env.EmailTemplates(ctx); err != nil || len(items) != 1 || !items[0].Customized {
		t.Fatalf("templates = %+v %v", items, err)
	}
	if tpl, err := env.EmailTemplate(ctx, EmailLogin, "es"); err != nil || tpl.Template.Subject != "Hola" || tpl.Placeholders[0] != "code" {
		t.Fatalf("template = %+v %v", tpl, err)
	}
	env.SetEmailTemplate(ctx, EmailLogin, "es", EmailCopy{Subject: "Hola"})
	env.ResetEmailTemplate(ctx, EmailLogin, "es")
	if locales, err := env.Locales(ctx); err != nil || len(locales) != 1 || locales[0].Name != "Español" {
		t.Fatalf("locales = %+v %v", locales, err)
	}
	if _, err := env.EmailTemplate(ctx, "../x", "es"); err == nil {
		t.Fatal("unsafe segment accepted")
	}

	base := "/management/v1/environments/env-1/"
	expected := []string{
		"PUT " + base + "delivery", "GET " + base + "delivery", "PUT " + base + "delivery", "POST " + base + "delivery/preview",
		"GET " + base + "delivery/preview?locale=es&purpose=invitation", "GET " + base + "delivery/templates", "GET " + base + "delivery/templates/login/es", "PUT " + base + "delivery/templates/login/es",
		"DELETE " + base + "delivery/templates/login/es", "GET " + base + "login-settings/locales",
	}
	if strings.Join(calls, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	wantBodies := map[int]string{
		0: `{"provider":"smtp","from_email":"no-reply@acme.io","smtp_host":"smtp.acme.io","smtp_port":587,"smtp_username":"mailer","smtp_tls":"starttls"}`,
		2: `{"webhook_url":"https://mail.example/hook","webhook_token":"tok"}`,
		3: `{"purpose":"login","locale":"es","template":{"subject":"Hola","heading":"","body":"","action":"","footer":""}}`,
	}
	for i, want := range wantBodies {
		if bodies[i] != want {
			t.Errorf("body[%d] = %s, want %s", i, bodies[i], want)
		}
	}
}

func TestSigningKeyRoutes(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path+" "+string(b))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"kid":"k1","state":"next","public_jwk":{"kid":"k1"}}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	key, err := env.CreateSigningKey(ctx)
	if err != nil || key.ID != "k1" || key.State != "next" || len(key.PublicJWK) == 0 {
		t.Fatalf("create = %+v %v", key, err)
	}
	env.SigningKeys(ctx)
	env.SigningKey(ctx, "k1")
	env.ActivateSigningKey(ctx, "k1")
	env.RetireSigningKey(ctx, "k1", true)
	if _, err = env.SigningKey(ctx, "../x"); err == nil {
		t.Fatal("unsafe kid accepted")
	}
	want := []string{
		"POST /management/v1/environments/env-1/signing-keys ",
		"GET /management/v1/environments/env-1/signing-keys ",
		"GET /management/v1/environments/env-1/signing-keys/k1 ",
		"POST /management/v1/environments/env-1/signing-keys/k1/activate ",
		"POST /management/v1/environments/env-1/signing-keys/k1/retire {\"force\":true}\n",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %q", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestLoginSettingsLocale(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"display_name":"Acme","locale":"es"}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	es := "es"
	out, err := env.SetLoginSettings(context.Background(), LoginSettings{DisplayName: "Acme", Locale: &es})
	if err != nil || out.Locale == nil || *out.Locale != "es" {
		t.Fatalf("settings = %+v %v", out, err)
	}
	env.SetLoginSettings(context.Background(), LoginSettings{DisplayName: "Acme"})
	if !strings.Contains(bodies[0], `"locale":"es"`) || strings.Contains(bodies[1], "locale") {
		t.Fatalf("bodies = %v", bodies)
	}
}

func TestClientAuthenticationRoutes(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+string(body))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"sa-1","token_endpoint_auth_method":"private_key_jwt"}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	out, err := env.SetServiceAccountAuthentication(ctx, "sa-1", ClientAuthentication{Method: AuthPrivateKeyJWT, JWKSURI: "https://keys.example/jwks"})
	if err != nil || out.Method != AuthPrivateKeyJWT {
		t.Fatalf("set = %+v %v", out, err)
	}
	method := AuthClientSecretPost
	if err = env.UpdateOAuthClient(ctx, "c-1", OAuthClientPatch{TokenEndpointAuthMethod: &method}); err != nil {
		t.Fatal(err)
	}
	if _, err = env.CreateOAuthClient(ctx, OAuthClient{ApplicationID: "a", ResourceID: "r", RedirectURIs: []string{"https://x"}, ClientAuthentication: ClientAuthentication{Method: AuthPrivateKeyJWT, JWKS: json.RawMessage(`{"keys":[]}`)}}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`PUT /management/v1/environments/env-1/service-accounts/sa-1/authentication {"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://keys.example/jwks"}`,
		`PATCH /management/v1/environments/env-1/oauth-clients/c-1 {"token_endpoint_auth_method":"client_secret_post"}`,
	}
	for i, w := range want {
		if strings.TrimSpace(got[i]) != w {
			t.Fatalf("request %d = %s", i, got[i])
		}
	}
	if !strings.Contains(got[2], `"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[]}`) {
		t.Fatalf("create = %s", got[2])
	}
	if _, err = env.SetServiceAccountImpersonation(ctx, "sa-1", true); err != nil {
		t.Fatal(err)
	}
	if w := `PUT /management/v1/environments/env-1/service-accounts/sa-1/impersonation {"allowed":true}`; strings.TrimSpace(got[3]) != w {
		t.Fatalf("impersonation = %s", got[3])
	}
}

func TestAccessTokenFormat(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, strings.TrimSpace(string(body)))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c-1"}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	if _, err := env.CreateOAuthClient(ctx, OAuthClient{ApplicationID: "a", ResourceID: "r", RedirectURIs: []string{"https://x"}, AccessTokenFormat: AccessTokenOpaque}); err != nil {
		t.Fatal(err)
	}
	format := AccessTokenJWT
	if err := env.UpdateOAuthClient(ctx, "c-1", OAuthClientPatch{AccessTokenFormat: &format}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got[0], `"access_token_format":"opaque"`) || got[1] != `{"access_token_format":"jwt"}` {
		t.Fatalf("requests = %v", got)
	}
}

func TestOAuthClientGrantTypes(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, strings.TrimSpace(string(body)))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"c-1"}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	if _, err := env.CreateOAuthClient(ctx, OAuthClient{ApplicationID: "a", ResourceID: "r", Public: true, HostedLogin: true, GrantTypes: []string{GrantDeviceCode, GrantRefreshToken}}); err != nil {
		t.Fatal(err)
	}
	grants := []string{GrantAuthorizationCode, GrantDeviceCode}
	if err := env.UpdateOAuthClient(ctx, "c-1", OAuthClientPatch{GrantTypes: &grants}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got[0], `"grant_types":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]`) || got[1] != `{"grant_types":["authorization_code","urn:ietf:params:oauth:grant-type:device_code"]}` {
		t.Fatalf("requests = %v", got)
	}
}

func TestFederationProviderOptionsWire(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = nil
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"conn-1"}`))
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	_, err := env.CreateFederation(ctx, Federation{Name: "Chat", Provider: ProviderOAuth2, ClientID: "c", ClientSecret: "s", UpdateProfile: true,
		Options: &FederationOptions{AuthorizeURL: "https://p/a", TokenURL: "https://p/t", UserinfoURL: "https://p/me", Scopes: []string{"identify"},
			Claims: &FederationClaimMap{Subject: "id", EmailVerified: "verified", Email: "email"}}})
	if err != nil {
		t.Fatal(err)
	}
	options := body["options"].(map[string]any)
	if body["update_profile"] != true || options["userinfo_url"] != "https://p/me" || options["claims"].(map[string]any)["email_verified"] != "verified" {
		t.Fatalf("create body = %v", body)
	}
	off := false
	if err := env.UpdateFederation(ctx, "conn-1", FederationPatch{UpdateProfile: &off}); err != nil {
		t.Fatal(err)
	}
	if v, ok := body["update_profile"]; !ok || v != false {
		t.Fatalf("patch body = %v", body)
	}
	_, err = env.CreateFederation(ctx, Federation{Name: "Okta", Provider: ProviderSAML, OrganizationID: "org-1",
		Options: &FederationOptions{MetadataURL: "https://idp/m", NameIDFormat: NameIDTransient, Attributes: &SAMLAttributes{Subject: "uid"}, SignRequests: true}})
	if err != nil {
		t.Fatal(err)
	}
	options = body["options"].(map[string]any)
	if body["provider"] != "saml" || options["metadata_url"] != "https://idp/m" || options["name_id_format"] != "transient" || options["attributes"].(map[string]any)["subject"] != "uid" || options["sign_requests"] != true {
		t.Fatalf("saml body = %v", body)
	}
	if _, ok := body["client_secret"]; ok {
		t.Fatalf("saml body has a secret: %v", body)
	}
}

func TestSAMLAppRoutes(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		calls = append(calls, r.Method+" "+r.URL.Path+" "+string(b))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"sp1","entity_id":"https://wiki.example.com/saml","acs_urls":["https://wiki.example.com/acs"],"attributes":{"mail":"email"},"items":[]}`))
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	sp, err := env.CreateSAMLApp(ctx, CreateSAMLApp{Name: "Wiki", Application: "a", Resource: "r", EntityID: "https://wiki.example.com/saml", ACSURLs: []string{"https://wiki.example.com/acs"}})
	if err != nil || sp.ID != "sp1" || sp.Attributes["mail"] != "email" {
		t.Fatalf("create = %+v %v", sp, err)
	}
	format := "persistent"
	env.SAMLIdentityProvider(ctx)
	env.SAMLApps(ctx)
	env.SAMLApp(ctx, "sp1")
	env.UpdateSAMLApp(ctx, "sp1", UpdateSAMLApp{NameIDFormat: &format})
	env.DeleteSAMLApp(ctx, "sp1")
	if _, err = env.SAMLApp(ctx, "../x"); err == nil {
		t.Fatal("unsafe id accepted")
	}
	want := []string{
		"POST /management/v1/environments/env-1/saml/service-providers {\"name\":\"Wiki\",\"application_id\":\"a\",\"resource_id\":\"r\",\"entity_id\":\"https://wiki.example.com/saml\",\"acs_urls\":[\"https://wiki.example.com/acs\"]}\n",
		"GET /management/v1/environments/env-1/saml/identity-provider ",
		"GET /management/v1/environments/env-1/saml/service-providers ",
		"GET /management/v1/environments/env-1/saml/service-providers/sp1 ",
		"PATCH /management/v1/environments/env-1/saml/service-providers/sp1 {\"name_id_format\":\"persistent\"}\n",
		"DELETE /management/v1/environments/env-1/saml/service-providers/sp1 ",
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %q", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("call[%d] = %q, want %q", i, calls[i], want[i])
		}
	}
}

func TestResourceGrantRoutes(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.Path+" "+strings.TrimSpace(string(body)))
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/resource-grants"):
			w.Write([]byte(`{"items":[{"id":"g1","resource_id":"r1","organization_id":"o2","role_ids":["x"]}],"page":{"total":1,"limit":50,"offset":0}}`))
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/access"), r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			w.Write([]byte(`{"id":"g1","resource_id":"r1","organization_id":"o2","role_ids":null}`))
		}
	}))
	defer srv.Close()
	env := New(srv.URL, "ik_mgmt_test").Environment("env-1")
	ctx := context.Background()
	if err := env.SetResourceAccess(ctx, "r1", ResourceAccess{RequireGrant: true}); err != nil {
		t.Fatal(err)
	}
	grants, err := env.ResourceGrants(ctx)
	if err != nil || len(grants) != 1 || grants[0].RoleIDs[0] != "x" {
		t.Fatalf("grants = %+v, %v", grants, err)
	}
	if _, err := env.PutResourceGrant(ctx, ResourceGrant{ResourceID: "r1", OrganizationID: "o2", RoleIDs: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.ResourceGrant(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	if err := env.DeleteResourceGrant(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.ResourceGrant(ctx, "../x"); err == nil {
		t.Fatal("unsafe segment accepted")
	}
	base := "/management/v1/environments/env-1/"
	want := []string{
		"PUT " + base + `resources/r1/access {"owner_organization_id":null,"require_grant":true}`,
		"GET " + base + "resource-grants ",
		"PUT " + base + `resource-grants {"resource_id":"r1","organization_id":"o2","role_ids":["x"]}`,
		"GET " + base + "resource-grants/g1 ",
		"DELETE " + base + "resource-grants/g1 ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
