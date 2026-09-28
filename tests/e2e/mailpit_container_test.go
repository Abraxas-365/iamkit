package e2e_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/bootstrap"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authmail"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication/authmodule"
	"github.com/gofiber/fiber/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// mailpitImage is a real SMTP server (AUTH PLAIN, MIME parsing) with an
// HTTP API to read what it received.
const mailpitImage = "axllent/mailpit:v1.30.6"

type mailpit struct {
	t        *testing.T
	Host     string // loopback: IAMKit talks plaintext only there
	SMTPPort int
	api      string
}

type mailpitMessage struct {
	ID      string
	Subject string
	Text    string
	HTML    string
	From    struct{ Name, Address string }
	To      []struct{ Name, Address string }
	ReplyTo []struct{ Name, Address string }
}

// startMailpit runs Mailpit requiring SMTP AUTH user:password.
func startMailpit(t *testing.T, user, password string) *mailpit {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, mailpitImage,
		testcontainers.WithExposedPorts("1025/tcp", "8025/tcp"),
		testcontainers.WithEnv(map[string]string{"MP_SMTP_AUTH": user + ":" + password, "MP_SMTP_AUTH_ALLOW_INSECURE": "true"}),
		testcontainers.WithWaitStrategyAndDeadline(90*time.Second, wait.ForHTTP("/api/v1/info").WithPort("8025/tcp")))
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatal(err)
	}
	smtpEndpoint, err := c.PortEndpoint(ctx, "1025/tcp", "")
	if err != nil {
		t.Fatal(err)
	}
	_, rawPort, err := net.SplitHostPort(smtpEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	smtpPort, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	api, err := c.PortEndpoint(ctx, "8025/tcp", "http")
	if err != nil {
		t.Fatal(err)
	}
	return &mailpit{t: t, Host: "127.0.0.1", SMTPPort: smtpPort, api: strings.Replace(api, "localhost", "127.0.0.1", 1)}
}

func (m *mailpit) get(path string, out any) {
	m.t.Helper()
	res, err := http.Get(m.api + path)
	if err != nil {
		m.t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		m.t.Fatalf("mailpit %s: %d", path, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		m.t.Fatal(err)
	}
}

// Last returns the newest message sent to address, parsed by Mailpit.
func (m *mailpit) Last(address string) mailpitMessage {
	m.t.Helper()
	var list struct {
		Messages []struct{ ID string }
	}
	for i := 0; i < 50; i++ {
		m.get("/api/v1/search?query="+url.QueryEscape("to:"+address), &list)
		if len(list.Messages) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(list.Messages) == 0 {
		m.t.Fatalf("no email for %s", address)
	}
	var msg mailpitMessage
	m.get("/api/v1/message/"+list.Messages[0].ID, &msg)
	return msg
}

func (m *mailpit) Count() int {
	m.t.Helper()
	var list struct{ Total int }
	m.get("/api/v1/messages", &list)
	return list.Total
}

// TestMailpitSMTP sends through a real SMTP server (Mailpit): AUTH with the
// sealed password, MIME that a real parser decodes (folded non-ASCII
// headers, HTML + text), a login completed with the mailed code, invitation
// links, rejected credentials, and the kept-secret rule when the server
// changes.
func TestMailpitSMTP(t *testing.T) {
	requireE2E(t)
	mp := startMailpit(t, "mailer", "s3cret-pass")
	e := newEnv(t, loopbackMail(authmodule.Mail{}))
	cfg := fiber.Map{"provider": "smtp", "from_email": "no-reply@acme.io", "from_name": "Équipe Acme Sécurité", "reply_to": "help@acme.io",
		"smtp_host": mp.Host, "smtp_port": mp.SMTPPort, "smtp_username": "mailer", "smtp_password": "s3cret-pass"}
	e.Must("PUT", e.Base+"/delivery", e.Owner, cfg, 204)

	a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON
	if a["delivered"] != true {
		t.Fatalf("test send = %v", a)
	}
	m := mp.Last("ops@example.com")
	if m.Subject != "Test email from IAMKit" || m.From.Name != "Équipe Acme Sécurité" || m.From.Address != "no-reply@acme.io" ||
		len(m.ReplyTo) != 1 || m.ReplyTo[0].Address != "help@acme.io" || !strings.Contains(m.HTML, "Email delivery works") || !strings.Contains(m.Text, "Email delivery works") {
		t.Fatalf("test email = %+v", m)
	}

	// A long non-ASCII subject is folded and still decodes to the original.
	long := "{{code}} — código de acceso para {{app_name}}: úsalo en los próximos minutos, por favor 🔐"
	e.Must("PUT", e.Base+"/login-settings", e.Owner, fiber.Map{"display_name": "Acme Ñandú", "locale": "es"}, 200)
	e.Must("PUT", e.Base+"/delivery/templates/login/es", e.Owner, fiber.Map{"subject": long}, 200)
	e.Must("PATCH", e.Base+"/users/"+e.Alice, e.Owner, fiber.Map{"otp_enabled": true}, 204)
	challenge := e.Must("POST", "/identity/v1/challenges", "", fiber.Map{"environment_id": e.EnvID, "email": e.AliceEmail, "purpose": "login"}, 202).JSON
	m = mp.Last(e.AliceEmail)
	code := mailCode.FindString(m.Text)
	want := strings.NewReplacer("{{code}}", code, "{{app_name}}", "Acme Ñandú").Replace(long)
	if code == "" || m.Subject != want || !strings.Contains(m.HTML, code) {
		t.Fatalf("login email subject %q (want %q): %+v", m.Subject, want, m)
	}
	// The code from the real mailbox signs the user in, once.
	verify := fiber.Map{"environment_id": e.EnvID, "organization_id": e.Org, "application_id": e.Client, "resource_id": e.Res,
		"challenge_id": challenge["challenge_id"], "purpose": "login", "code": code}
	if pair := e.Must("POST", "/identity/v1/challenges/verify", "", verify, 200).JSON; pair["access_token"] == nil {
		t.Fatalf("login = %v", pair)
	}
	e.Must("POST", "/identity/v1/challenges/verify", "", verify, 401)

	// Invitations carry a working hosted link.
	inv := e.Must("POST", e.Base+"/organizations/"+e.Org+"/invitations", e.Owner, fiber.Map{"email": "bob@example.com"}, 201).JSON
	if m = mp.Last("bob@example.com"); inv["delivery"] != "sent" || !strings.Contains(m.Text, "/hosted/invite?token="+inv["token"].(string)) {
		t.Fatalf("invitation %v: %+v", inv, m)
	}

	// Changing the server requires the password again; a wrong one is
	// reported as rejected credentials by the real server.
	keep := fiber.Map{}
	for k, v := range cfg {
		keep[k] = v
	}
	delete(keep, "smtp_password")
	keep["smtp_host"] = "localhost"
	e.Must("PUT", e.Base+"/delivery", e.Owner, keep, 400)
	keep["smtp_password"] = "wrong"
	e.Must("PUT", e.Base+"/delivery", e.Owner, keep, 204)
	before := mp.Count()
	if a = e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON; a["delivered"] != false || a["reason"] != "email provider rejected the credentials" {
		t.Fatalf("wrong password = %v", a)
	}
	if mp.Count() != before {
		t.Fatal("mail accepted with a wrong password")
	}
	if s := e.Must("GET", e.Base+"/delivery/status", e.Owner, nil, 200).JSON; s["last_failure"] == nil {
		t.Fatalf("status after failure = %v", s)
	}
}

// TestMailpitGlobalSMTP: the deployment-wide sender reaches a real server.
func TestMailpitGlobalSMTP(t *testing.T) {
	requireE2E(t)
	mp := startMailpit(t, "global", "global-pass")
	global := &authmodule.Sender{Provider: "smtp", From: "no-reply@iam.example", FromName: "IAM",
		Mailer: authmail.SMTP{Host: mp.Host, Port: mp.SMTPPort, TLS: "starttls", Username: "global", Password: "global-pass", Dial: (&net.Dialer{}).DialContext}}
	e := newEnv(t, bootstrap.WithMail(authmodule.Mail{Global: global}))
	if a := e.Must("POST", e.Base+"/delivery/test", e.Owner, fiber.Map{"email": "ops@example.com"}, 200).JSON; a["delivered"] != true || a["source"] != "global" {
		t.Fatalf("global test = %v", a)
	}
	if m := mp.Last("ops@example.com"); m.From.Address != "no-reply@iam.example" || m.Subject != "Test email from IAMKit" {
		t.Fatalf("global email = %+v", m)
	}
}
