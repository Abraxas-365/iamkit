package e2e_test

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/cryptox"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
)

var mailCode = regexp.MustCompile(`\b\d{8}\b`)

// loopbackMail lets environment SMTP servers be reached on loopback, where
// the production dialer refuses to go.
func loopbackMail(extra authmodule.Mail) bootstrap.Option {
	extra.Dial = (&net.Dialer{}).DialContext
	return bootstrap.WithMail(extra)
}

func (e *Env) sealedSecret() string {
	e.t.Helper()
	var sealed string
	if err := e.DB.Get(&sealed, `SELECT secret_sealed FROM delivery_configs WHERE environment_id=$1`, e.EnvID); err != nil {
		e.t.Fatal(err)
	}
	return sealed
}

// TestSMTPDelivery covers an environment SMTP server: the password sealed
// and kept across updates, rendered challenge and invitation emails that
// work end to end, the language (request, environment default, ignored
// unknown) and saved wording, credential failures, and switching back to
// the webhook.
func TestSMTPDelivery(t *testing.T) {
	smtp := newFakeSMTP(t)
	e := newEnv(t, loopbackMail(authmodule.Mail{}))
	smtpConfig := fiber.Map{"provider": "smtp", "from_email": "No-Reply@Acme.io", "from_name": "Acme Mail", "reply_to": "help@acme.io",
		"smtp_host": "127.0.0.1", "smtp_port": smtp.Port, "smtp_username": "mailer", "smtp_password": "s3cret-pass"}

	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "127.0.0.1", "smtp_username": "mailer"}, 400)
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "127.0.0.1", "webhook_url": "https://hook.example"}, 400)
	e.Must("PUT", e.Base+"/delivery", e.Owner, smtpConfig, 204)
	cfg := e.Must("GET", e.Base+"/delivery", e.Owner, nil, 200)
	if cfg.JSON["provider"] != "smtp" || cfg.JSON["from_email"] != "no-reply@acme.io" || cfg.JSON["smtp_tls"] != "starttls" || cfg.JSON["has_secret"] != true || strings.Contains(cfg.Body, "s3cret") {
		t.Fatalf("config = %s", cfg.Body)
	}
	if sealed := e.sealedSecret(); !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, "s3cret") {
		t.Fatalf("stored secret = %q", sealed)
	}
	if s := e.Must("GET", e.Base+"/delivery/status", e.Owner, nil, 200).JSON; s["source"] != "environment" || s["provider"] != "smtp" {
		t.Fatalf("status = %v", s)
	}

	// Test send: rendered in the default brand and language.
	a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != true || a["source"] != "environment" {
		t.Fatalf("test = %v", a)
	}
	m := smtp.Last()
	if m.User != "mailer" || m.Password != "s3cret-pass" || !strings.Contains(m.From, "Acme Mail") || !strings.Contains(m.From, "no-reply@acme.io") ||
		!strings.Contains(m.ReplyTo, "help@acme.io") || m.To != "<ops@example.com>" || m.Subject != "Test email from IAMKit" || !strings.Contains(m.HTML, "Email delivery works") {
		t.Fatalf("test email = %+v", m)
	}
	if len(e.Mail.Sent) != 0 {
		t.Fatal("the global delivery was used")
	}

	// Updating without the password keeps it.
	keep := fiber.Map{}
	for k, v := range smtpConfig {
		keep[k] = v
	}
	delete(keep, "smtp_password")
	keep["from_name"] = "Acme"
	e.Must("PUT", e.Base+"/delivery", e.Owner, keep, 204)
	e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200)
	if m = smtp.Last(); m.Password != "s3cret-pass" || !strings.Contains(m.From, "Acme") {
		t.Fatalf("kept secret: %+v", m)
	}
	// The stored password never follows a different server or account.
	moved := fiber.Map{}
	for k, v := range keep {
		moved[k] = v
	}
	moved["smtp_host"] = "smtp.example.net"
	if r := e.Must("PUT", e.Base+"/delivery", e.Owner, moved, 400); !strings.Contains(r.Body, "smtp_password is required when changing") {
		t.Fatalf("moved server kept the password: %s", r.Body)
	}
	moved["smtp_host"], moved["smtp_username"] = "127.0.0.1", "someone-else"
	e.Must("PUT", e.Base+"/delivery", e.Owner, moved, 400)
	if cfg := e.Must("GET", e.Base+"/delivery", e.Owner, nil, 200).JSON; cfg["smtp_username"] != "mailer" {
		t.Fatalf("rejected update was stored: %v", cfg)
	}

	// A password reset works with the code from the email.
	reset := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "password_reset"}, 202).JSON
	m = smtp.Last()
	code := mailCode.FindString(m.Text)
	if m.To != "<"+e.AliceEmail+">" || m.Subject != "Reset your IAMKit password" || code == "" || !strings.Contains(m.HTML, code) || !strings.Contains(m.Text, "5 minutes") {
		t.Fatalf("reset email = %+v", m)
	}
	e.Must("POST", "/identity/v1/challenges/verify", "", fiber.Map{"environment_id": e.EnvID, "challenge_id": reset["challenge_id"], "purpose": "password_reset", "code": code, "password": "another long password"}, 204)
	e.Pass = "another long password"
	e.Login(e.AliceEmail)

	// Language: environment default (with brand), the request's own, and an
	// unavailable one falling back to the default.
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"display_name": "Acme", "locale": "eo"}, 400)
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"display_name": "Acme", "locale": "ES"}, 200)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"otp_enabled": true}, 204)
	login := func(locale string) sentEmail {
		t.Helper()
		e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "login", "locale": locale}, 202)
		return smtp.Last()
	}
	if m = login(""); m.Subject != "Tu código de acceso a Acme" || !strings.Contains(m.HTML, `lang="es"`) {
		t.Fatalf("environment language: %+v", m)
	}
	if m = login("en-US"); m.Subject != "Your sign-in code for Acme" {
		t.Fatalf("requested language: %+v", m)
	}
	if m = login("eo"); m.Subject != "Tu código de acceso a Acme" {
		t.Fatalf("unavailable language: %+v", m)
	}

	// Saved wording replaces the default in that language only.
	e.Must("PUT", e.Base+"/delivery/templates/login/es", e.Owner, fiber.Map{"subject": "{{code}} es tu código de {{app_name}}", "footer": "Equipo Acme"}, 200)
	if m = login(""); m.Subject != mailCode.FindString(m.Text)+" es tu código de Acme" || !strings.Contains(m.Text, "Equipo Acme") || !strings.Contains(m.Text, "Vence en 5 minutos") {
		t.Fatalf("saved wording: %+v", m)
	}

	// Invitations link to the hosted page (no invitation_url configured).
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "bob@example.com"}, 201).JSON
	token := inv["token"].(string)
	m = smtp.Last()
	if inv["delivery"] != "sent" || m.To != "<bob@example.com>" || m.Subject != "Te invitaron a unirte a Acme" || !strings.Contains(m.HTML, "Aceptar invitación") ||
		!strings.Contains(m.Text, "https://iam.example/hosted/invite?token="+token) {
		t.Fatalf("invitation %v email = %+v", inv, m)
	}

	// Rejected credentials are reported without details.
	smtp.mu.Lock()
	smtp.authReply = "535 5.7.8 bad credentials for mailer"
	smtp.mu.Unlock()
	a = e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != false || a["reason"] != "email provider rejected the credentials" || a["status"] != nil {
		t.Fatalf("bad credentials = %v", a)
	}

	// Back to the webhook: the SMTP secret is dropped.
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": "https://hook.example/mail", "webhook_token": "t"}, 204)
	if cfg := e.Must("GET", e.Base+"/delivery", e.Owner, nil, 200).JSON; cfg["provider"] != "webhook" || cfg["has_secret"] != false || cfg["smtp_host"] != "" || e.sealedSecret() != "" {
		t.Fatalf("switched = %v", cfg)
	}
	if n := e.audited("delivery.update", "/environments/"+e.EnvID+"/delivery"); n != 3 {
		t.Fatalf("audited updates = %d", n)
	}
	var leaked int
	if err := e.DB.Get(&leaked, `SELECT count(*) FROM audit_events WHERE target_id LIKE '%s3cret%' OR target_id LIKE '%127.0.0.1%'`); err != nil || leaked != 0 {
		t.Fatalf("audit leaks: %d %v", leaked, err)
	}
}

// TestSMTPDeliveryGuarded: without the test dialer, environment SMTP
// servers on private addresses are refused.
func TestSMTPDeliveryGuarded(t *testing.T) {
	smtp := newFakeSMTP(t)
	e := newEnv(t)
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "127.0.0.1", "smtp_port": smtp.Port}, 204)
	a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != false || a["reason"] != "email provider address is not allowed" || len(smtp.Sent()) != 0 {
		t.Fatalf("private SMTP = %v", a)
	}
}

// TestResendDelivery covers an environment Resend key: required, sealed,
// kept, sent with the environment's sender, and API failures classified.
func TestResendDelivery(t *testing.T) {
	resend := newFakeResend(t)
	e := newEnv(t, bootstrap.WithMail(authmodule.Mail{ResendEndpoint: resend.URL + "/emails", ResendClient: http.DefaultTransport}))
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "resend", "from_email": "no-reply@acme.io"}, 400)
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "resend", "from_email": "no-reply@acme.io", "api_key": "re_123", "smtp_host": "smtp.acme.io"}, 400)
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "resend", "from_email": "no-reply@acme.io", "from_name": "Acme", "api_key": "re_123"}, 204)
	if sealed := e.sealedSecret(); !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, "re_123") {
		t.Fatalf("stored key = %q", sealed)
	}
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "resend", "from_email": "no-reply@acme.io", "from_name": "Acme Billing"}, 204)

	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"otp_enabled": true}, 204)
	e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "login", "locale": "es"}, 202)
	m := resend.Last(t)
	if m.APIKey != "re_123" || m.From != `"Acme Billing" <no-reply@acme.io>` || m.To != e.AliceEmail || m.Subject != "Tu código de acceso a IAMKit" ||
		mailCode.FindString(m.Text) == "" || !strings.Contains(m.HTML, mailCode.FindString(m.Text)) {
		t.Fatalf("resend email = %+v", m)
	}

	resend.Answer(403, `{"name":"invalid_api_key","message":"API key is invalid"}`)
	if a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON; a["delivered"] != false || a["reason"] != "email provider rejected the credentials" {
		t.Fatalf("invalid key = %v", a)
	}
	resend.Answer(422, `{"name":"validation_error","message":"domain not verified"}`)
	a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != false || a["reason"] != "email provider rejected the request" || a["status"] != float64(422) {
		t.Fatalf("rejected = %v", a)
	}
	if last := e.Must("GET", e.Base+"/delivery/status", e.Owner, nil, 200).JSON["last_failure"].(map[string]any); last["reason"] != "email provider rejected the request" {
		t.Fatalf("recorded failure = %v", last)
	}
}

// TestProviderSecretsNeedKey: without IAMKIT_ENCRYPTION_KEY provider
// secrets cannot be stored (422); what needs none still works.
func TestProviderSecretsNeedKey(t *testing.T) {
	e := newEnv(t, bootstrap.WithSealer(&cryptox.Sealer{}))
	if r := e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "resend", "from_email": "no-reply@acme.io", "api_key": "re_123"}, 422); !strings.Contains(r.Body, "IAMKIT_ENCRYPTION_KEY") || r.JSON["error"].(map[string]any)["code"] != "ENCRYPTION_KEY_REQUIRED" {
		t.Fatalf("resend without key: %s", r.Body)
	}
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "smtp.acme.io", "smtp_username": "u", "smtp_password": "p"}, 422)
	e.Must("GET", e.Base+"/delivery", e.Owner, nil, 404)
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "smtp_host": "smtp.acme.io"}, 204)
	e.Must("PUT", e.Base+"/delivery", e.Owner, fiber.Map{"webhook_url": "https://hook.example/mail", "webhook_token": "t"}, 204)
}

// TestGlobalSMTP: a deployment-wide SMTP sender serves environments
// without their own configuration, rendering in each one's brand.
func TestGlobalSMTP(t *testing.T) {
	smtp := newFakeSMTP(t)
	global := &authmodule.Sender{Provider: "smtp", From: "no-reply@iam.example", FromName: "IAM",
		Mailer: authmail.SMTP{Host: "127.0.0.1", Port: smtp.Port, TLS: "starttls", Dial: (&net.Dialer{}).DialContext}}
	e := newEnv(t, bootstrap.WithMail(authmodule.Mail{Global: global, Locale: "es"}))
	if s := e.Must("GET", e.Base+"/delivery/status", e.Owner, nil, 200).JSON; s["source"] != "global" || s["provider"] != "smtp" || s["global_configured"] != true {
		t.Fatalf("status = %v", s)
	}
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"display_name": "Acme"}, 200)
	a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	m := smtp.Last()
	if a["delivered"] != true || a["source"] != "global" || m.Subject != "Correo de prueba de Acme" || !strings.Contains(m.From, "no-reply@iam.example") || len(e.Mail.Sent) != 0 {
		t.Fatalf("global test %v: %+v", a, m)
	}
	// Invitations link to the hosted page, as they are rendered here.
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "bob@example.com"}, 201).JSON
	if link, _ := inv["link"].(string); inv["delivery"] != "sent" || !strings.HasPrefix(link, "https://iam.example/hosted/invite?token=ik_inv_") || !strings.Contains(smtp.Last().Text, link) {
		t.Fatalf("invitation = %v", inv)
	}
}
