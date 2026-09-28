package authmail

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
)

// fakeSMTP is a minimal SMTP server for tests: STARTTLS or implicit TLS
// with httptest's certificate (valid for example.com and 127.0.0.1),
// PLAIN auth, and scripted failures.
type fakeSMTP struct {
	implicit  bool // TLS from the first byte
	noTLS     bool // don't offer STARTTLS
	noAuth    bool // don't offer AUTH
	authReply string
	rcptReply string
	stall     bool // accept and never greet

	listener net.Listener
	cert     tls.Certificate
	pool     *x509.CertPool

	mu       sync.Mutex
	tls      bool
	user     string
	password string
	from, to string
	data     string
}

func newFakeSMTP(t *testing.T, f *fakeSMTP) *fakeSMTP {
	t.Helper()
	ts := httptest.NewTLSServer(nil) // only for its certificate
	f.cert = ts.TLS.Certificates[0]
	f.pool = x509.NewCertPool()
	f.pool.AddCert(ts.Certificate())
	ts.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.listener = l
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

// client configures an SMTP sender for host (whose name the certificate
// must cover) that dials this server whatever the host resolves to.
func (f *fakeSMTP) client(host string) SMTP {
	tlsMode := authentication.SMTPStartTLS
	if f.implicit {
		tlsMode = authentication.SMTPImplicitTLS
	}
	addr := f.listener.Addr().String()
	return SMTP{Host: host, Port: 587, TLS: tlsMode, TLSConfig: &tls.Config{RootCAs: f.pool},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}
}

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	if f.stall {
		io.Copy(io.Discard, conn)
		return
	}
	secure := false
	if f.implicit {
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
		secure = true
	}
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	reply := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch verb {
		case "EHLO", "HELO":
			lines := []string{"250-fake"}
			if !secure && !f.noTLS {
				lines = append(lines, "250-STARTTLS")
			}
			if !f.noAuth {
				lines = append(lines, "250-AUTH PLAIN")
			}
			lines = append(lines, "250 8BITMIME")
			reply(strings.Join(lines, "\r\n"))
		case "STARTTLS":
			reply("220 go ahead")
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if tlsConn.Handshake() != nil {
				return
			}
			conn, secure = tlsConn, true
			r, w = bufio.NewReader(conn), bufio.NewWriter(conn)
		case "AUTH":
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			parts := strings.Split(string(raw), "\x00")
			f.mu.Lock()
			if len(parts) == 3 {
				f.user, f.password = parts[1], parts[2]
			}
			f.mu.Unlock()
			if f.authReply != "" {
				reply(f.authReply)
				continue
			}
			reply("235 ok")
		case "MAIL":
			f.mu.Lock()
			f.from, f.tls = line, secure
			f.mu.Unlock()
			reply("250 ok")
		case "RCPT":
			f.mu.Lock()
			f.to = line
			f.mu.Unlock()
			if f.rcptReply != "" {
				reply(f.rcptReply)
				continue
			}
			reply("250 ok")
		case "DATA":
			reply("354 go")
			var data strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				data.WriteString(strings.TrimPrefix(l, "."))
			}
			f.mu.Lock()
			f.data = data.String()
			f.mu.Unlock()
			reply("250 queued")
		case "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func TestSMTPDeliverSTARTTLS(t *testing.T) {
	f := newFakeSMTP(t, &fakeSMTP{})
	s := f.client("example.com")
	s.Username, s.Password = "apikey", "s3cret"
	if err := s.Deliver(context.Background(), testEmail()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.tls || f.user != "apikey" || f.password != "s3cret" || !strings.HasPrefix(f.from, "MAIL FROM:<no-reply@acme.io>") || f.to != "RCPT TO:<ana@example.com>" {
		t.Fatalf("tls %v user %q from %q to %q", f.tls, f.user, f.from, f.to)
	}
	msg, err := mail.ReadMessage(strings.NewReader(f.data))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	from, _ := mail.ParseAddress(msg.Header.Get("From"))
	if subject != "Tu código" || from.Name != "Acme, Inc." || from.Address != "no-reply@acme.io" ||
		msg.Header.Get("Reply-To") != "<help@acme.io>" || msg.Header.Get("To") != "<ana@example.com>" ||
		msg.Header.Get("MIME-Version") != "1.0" || !strings.HasSuffix(msg.Header.Get("Message-ID"), "@acme.io>") || msg.Header.Get("Date") == "" {
		t.Fatalf("headers %v", msg.Header)
	}
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	parts := multipart.NewReader(msg.Body, params["boundary"])
	var got []string
	for {
		p, err := parts.NextPart()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(quotedprintable.NewReader(p))
		got = append(got, p.Header.Get("Content-Type")+"|"+string(body))
	}
	if len(got) != 2 || got[0] != "text/plain; charset=utf-8|hi" || got[1] != "text/html; charset=utf-8|<p>hi</p>" {
		t.Fatalf("parts %q", got)
	}
}

func TestSMTPDeliverImplicitTLSWithoutAuth(t *testing.T) {
	f := newFakeSMTP(t, &fakeSMTP{implicit: true})
	if err := f.client("example.com").Deliver(context.Background(), testEmail()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.tls || f.user != "" || f.data == "" {
		t.Fatalf("tls %v user %q", f.tls, f.user)
	}
}

func TestSMTPFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server *fakeSMTP
		auth   bool
		reason string
	}{
		{"no STARTTLS on a remote host", &fakeSMTP{noTLS: true}, false, "SMTP server rejected the message"},
		{"bad credentials", &fakeSMTP{authReply: "535 5.7.8 authentication failed"}, true, "email provider rejected the credentials"},
		{"no AUTH offered", &fakeSMTP{noAuth: true}, true, "email provider rejected the credentials"},
		{"recipient refused", &fakeSMTP{rcptReply: "550 5.1.1 no such user"}, false, "SMTP server rejected the message"},
		{"temporary failure", &fakeSMTP{rcptReply: "451 4.3.0 try later"}, false, "SMTP server rejected the message"},
	} {
		f := newFakeSMTP(t, tc.server)
		s := f.client("example.com")
		if tc.auth {
			s.Username, s.Password = "u", "p"
		}
		err := s.Deliver(context.Background(), testEmail())
		status, reason := authentication.Describe(err)
		if reason != tc.reason || status != nil {
			t.Errorf("%s: %q %v (%v)", tc.name, reason, status, err)
		}
		if strings.Contains(reason, "no such user") || strings.Contains(reason, "example.com") {
			t.Errorf("%s: reason leaks server text: %q", tc.name, reason)
		}
	}
}

// A certificate that doesn't match the host is refused, never ignored.
func TestSMTPVerifiesCertificate(t *testing.T) {
	f := newFakeSMTP(t, &fakeSMTP{})
	err := f.client("mail.acme.io").Deliver(context.Background(), testEmail())
	if _, reason := authentication.Describe(err); reason != "email provider could not be reached" {
		t.Fatalf("reason %q (%v)", reason, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.from != "" {
		t.Fatal("sent over an unverified connection")
	}
}

// A loopback mail catcher without STARTTLS is allowed (development).
func TestSMTPLoopbackPlaintext(t *testing.T) {
	f := newFakeSMTP(t, &fakeSMTP{noTLS: true})
	if err := f.client("127.0.0.1").Deliver(context.Background(), testEmail()); err != nil {
		t.Fatal(err)
	}
}

func TestSMTPTimeoutAndGuard(t *testing.T) {
	f := newFakeSMTP(t, &fakeSMTP{stall: true})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := f.client("example.com").Deliver(ctx, testEmail())
	if code(err) != authentication.CodeProviderTimeout {
		t.Fatalf("stall: %v", err)
	}

	// Without a Dial override, private and loopback addresses are refused.
	plain := newFakeSMTP(t, &fakeSMTP{})
	_, port, _ := net.SplitHostPort(plain.listener.Addr().String())
	s := SMTP{Host: "127.0.0.1", TLS: authentication.SMTPStartTLS}
	s.Port, _ = strconv.Atoi(port)
	if err := s.Deliver(context.Background(), testEmail()); code(err) != authentication.CodeDeliveryAddress {
		t.Fatalf("guard: %v", err)
	}
	plain.mu.Lock()
	defer plain.mu.Unlock()
	if plain.from != "" {
		t.Fatal("guarded dial reached the server")
	}
}

// Header values can never start a new header line.
func TestSMTPMessageHeaderInjection(t *testing.T) {
	e := testEmail()
	e.Subject = "Hi\r\nBcc: evil@x.io"
	e.FromName = "Acme\r\nBcc: evil@x.io"
	raw, err := message(e, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("injected header in:\n%s", head)
		}
	}
}

// Long non-ASCII headers are folded, never beyond RFC 5322 line limits, and
// unfold back to the same value.
func TestSMTPMessageFoldsLongHeaders(t *testing.T) {
	e := testEmail()
	e.Subject = string([]rune(strings.Repeat("認証コードのお知らせ ", 20))[:200])
	e.FromName = strings.TrimSpace(strings.Repeat("Ñandú ", 16)[:95])
	raw, err := message(e, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	for _, line := range strings.Split(head, "\r\n") {
		// 998 is the hard limit; past 78 only a single unbreakable encoded
		// word ("Name: " prefix + ≤75) may remain.
		if len(line) > 998 || (len(line) > 78 && strings.Count(strings.TrimSpace(line[strings.Index(line, ":")+1:]), " ") > 0) {
			t.Fatalf("header line of %d chars: %q", len(line), line)
		}
	}
	if strings.Count(head, "\r\n ") < 3 {
		t.Fatalf("long headers were not folded:\n%s", head)
	}
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != singleLine(e.Subject) {
		t.Fatalf("subject round trip: %q %v", subject, err)
	}
	from, err := msg.Header.AddressList("From")
	if err != nil || len(from) != 1 || from[0].Name != e.FromName {
		t.Fatalf("from round trip: %+v %v", from, err)
	}
}
