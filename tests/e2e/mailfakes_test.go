package e2e_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// sentEmail is an email a fake provider received, decoded.
type sentEmail struct {
	From, To, ReplyTo, Subject string
	Text, HTML                 string
	User, Password             string // SMTP AUTH PLAIN credentials
	APIKey                     string // Resend bearer key
}

// fakeSMTP is a plaintext SMTP server on loopback (IAMKit allows plaintext
// only there) offering AUTH PLAIN; it records every message.
type fakeSMTP struct {
	t    *testing.T
	Port int

	mu   sync.Mutex
	sent []sentEmail
	// authReply, when set, answers AUTH (e.g. "535 bad credentials").
	authReply string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeSMTP{t: t, Port: l.Addr().(*net.TCPAddr).Port}
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

func (f *fakeSMTP) serve(conn net.Conn) {
	defer conn.Close()
	r, w := bufio.NewReader(conn), bufio.NewWriter(conn)
	reply := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
	var user, password string
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch strings.ToUpper(strings.SplitN(line, " ", 2)[0]) {
		case "EHLO", "HELO":
			reply("250-fake\r\n250-AUTH PLAIN\r\n250 8BITMIME")
		case "AUTH":
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
			if parts := strings.Split(string(raw), "\x00"); len(parts) == 3 {
				user, password = parts[1], parts[2]
			}
			f.mu.Lock()
			answer := f.authReply
			f.mu.Unlock()
			if answer != "" {
				reply(answer)
				continue
			}
			reply("235 ok")
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
			email := decodeMIME(f.t, data.String())
			email.User, email.Password = user, password
			f.mu.Lock()
			f.sent = append(f.sent, email)
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

// Sent returns the messages received so far.
func (f *fakeSMTP) Sent() []sentEmail {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentEmail(nil), f.sent...)
}

// Last returns the latest message, failing the test when there is none.
func (f *fakeSMTP) Last() sentEmail {
	f.t.Helper()
	sent := f.Sent()
	if len(sent) == 0 {
		f.t.Fatal("no email reached the SMTP server")
	}
	return sent[len(sent)-1]
}

// decodeMIME decodes the multipart/alternative message IAMKit writes.
func decodeMIME(t *testing.T, raw string) sentEmail {
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Errorf("read message: %v", err)
		return sentEmail{}
	}
	dec := new(mime.WordDecoder)
	subject, _ := dec.DecodeHeader(msg.Header.Get("Subject"))
	out := sentEmail{From: msg.Header.Get("From"), To: msg.Header.Get("To"), ReplyTo: msg.Header.Get("Reply-To"), Subject: subject}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Errorf("content type: %v", err)
		return out
	}
	parts := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := parts.NextPart()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(quotedprintable.NewReader(part))
		switch {
		case strings.HasPrefix(part.Header.Get("Content-Type"), "text/plain"):
			out.Text = string(body)
		case strings.HasPrefix(part.Header.Get("Content-Type"), "text/html"):
			out.HTML = string(body)
		}
	}
	return out
}

// fakeResend is the Resend send-email API; it answers with status (200 by
// default) and records every request.
type fakeResend struct {
	*httptest.Server
	mu     sync.Mutex
	sent   []sentEmail
	status int
	answer string
}

func newFakeResend(t *testing.T) *fakeResend {
	t.Helper()
	f := &fakeResend{status: 200}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			From    string   `json:"from"`
			To      []string `json:"to"`
			Subject string   `json:"subject"`
			HTML    string   `json:"html"`
			Text    string   `json:"text"`
			ReplyTo string   `json:"reply_to"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/emails" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body.To) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sent = append(f.sent, sentEmail{From: body.From, To: body.To[0], ReplyTo: body.ReplyTo, Subject: body.Subject, Text: body.Text, HTML: body.HTML,
			APIKey: strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
		w.WriteHeader(f.status)
		if f.answer != "" {
			w.Write([]byte(f.answer))
		} else {
			w.Write([]byte(`{"id":"` + strconv.Itoa(len(f.sent)) + `"}`))
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// Answer makes the API answer status with body from now on.
func (f *fakeResend) Answer(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.answer = status, body
}

func (f *fakeResend) Last(t *testing.T) sentEmail {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		t.Fatal("no email reached the Resend API")
	}
	return f.sent[len(f.sent)-1]
}
