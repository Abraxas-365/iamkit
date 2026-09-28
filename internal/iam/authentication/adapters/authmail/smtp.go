package authmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/netx"
)

// SMTP sends rendered email through an SMTP server over implicit TLS
// (port 465) or STARTTLS. STARTTLS is mandatory unless the host is a
// loopback address (a local mail catcher in development).
type SMTP struct {
	Host     string
	Port     int
	TLS      string // authentication.SMTPStartTLS or SMTPImplicitTLS
	Username string // empty: no AUTH
	Password string
	// Dial defaults to netx.GuardedDialer (public addresses only); the
	// deployment-wide server may dial anything.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// TLSConfig overrides the verification settings (tests); ServerName is
	// always the host.
	TLSConfig *tls.Config
}

var _ authentication.Mailer = SMTP{}

func (s SMTP) Deliver(ctx context.Context, email authentication.Email) error {
	msg, err := message(email, time.Now())
	if err != nil {
		return err
	}
	dial := s.Dial
	if dial == nil {
		dial = netx.GuardedDialer().DialContext
	}
	deadline := time.Now().Add(config.ExternalHTTPTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := dial(dialCtx, "tcp", net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	if err != nil {
		return networkFailure(err)
	}
	defer conn.Close()
	// Stop the whole exchange at the deadline or when the caller gives up.
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.TLSConfig != nil {
		tlsConfig = s.TLSConfig.Clone()
	}
	tlsConfig.ServerName = s.Host
	if s.TLS == authentication.SMTPImplicitTLS {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			return networkFailure(err)
		}
		conn = tlsConn
	}
	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return smtpFailure(err)
	}
	defer client.Close()
	if err := client.Hello(heloName(email.From)); err != nil {
		return smtpFailure(err)
	}
	if s.TLS != authentication.SMTPImplicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				return smtpFailure(err)
			}
		} else if !loopback(s.Host) {
			return authentication.DeliveryFailure(errx.External("smtp: server does not offer STARTTLS"), authentication.CodeSMTPRejected)
		}
	}
	if s.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return authentication.DeliveryFailure(errx.External("smtp: server does not offer AUTH"), authentication.CodeProviderAuth)
		}
		if err := client.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return smtpFailure(err)
		}
	}
	if err := client.Mail(email.From); err != nil {
		return smtpFailure(err)
	}
	if err := client.Rcpt(email.To); err != nil {
		return smtpFailure(err)
	}
	w, err := client.Data()
	if err != nil {
		return smtpFailure(err)
	}
	if _, err := w.Write(msg); err != nil {
		return smtpFailure(err)
	}
	if err := w.Close(); err != nil {
		return smtpFailure(err)
	}
	_ = client.Quit()
	return nil
}

// smtpFailure classifies an SMTP exchange error: a server reply (5xx/4xx)
// is a rejection, 535/534/530 of the credentials; anything else is the
// connection failing.
func smtpFailure(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		switch reply.Code {
		case 530, 534, 535:
			return authentication.DeliveryFailure(err, authentication.CodeProviderAuth)
		}
		return authentication.DeliveryFailure(err, authentication.CodeSMTPRejected)
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return authentication.DeliveryFailure(err, authentication.CodeProviderUnreachable)
	}
	return networkFailure(err)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// heloName is the sender's domain, a stable name that says who is sending.
func heloName(from string) string {
	if _, domain, ok := strings.Cut(from, "@"); ok && domain != "" {
		return domain
	}
	return "localhost"
}

// message builds the RFC 5322 message: multipart/alternative with the text
// and HTML parts, quoted-printable, headers encoded for non-ASCII text.
func message(email authentication.Email, now time.Time) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, errx.Wrap(err, "prepare email", errx.TypeInternal)
	}
	var body bytes.Buffer
	parts := multipart.NewWriter(&body)
	for _, part := range []struct{ contentType, content string }{
		{"text/plain; charset=utf-8", email.Text},
		{"text/html; charset=utf-8", email.HTML},
	} {
		w, err := parts.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.contentType},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, errx.Wrap(err, "prepare email", errx.TypeInternal)
		}
		qp := quotedprintable.NewWriter(w)
		if _, err := qp.Write([]byte(part.content)); err != nil {
			return nil, errx.Wrap(err, "prepare email", errx.TypeInternal)
		}
		if err := qp.Close(); err != nil {
			return nil, errx.Wrap(err, "prepare email", errx.TypeInternal)
		}
	}
	if err := parts.Close(); err != nil {
		return nil, errx.Wrap(err, "prepare email", errx.TypeInternal)
	}

	var out bytes.Buffer
	header := func(name, value string) { fmt.Fprintf(&out, "%s: %s\r\n", name, fold(len(name)+2, value)) }
	header("From", sender(email))
	header("To", (&mail.Address{Address: email.To}).String())
	if email.ReplyTo != "" {
		header("Reply-To", (&mail.Address{Address: email.ReplyTo}).String())
	}
	header("Subject", mime.QEncoding.Encode("utf-8", singleLine(email.Subject)))
	header("Date", now.UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+heloName(email.From)+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "multipart/alternative; boundary="+parts.Boundary())
	out.WriteString("\r\n")
	out.Write(body.Bytes())
	return out.Bytes(), nil
}

// fold keeps header lines within 78 characters (RFC 5322 §2.2.3) by breaking
// at spaces, which in encoded headers only ever separate encoded words
// (mime.QEncoding keeps each ≤75 characters). used is the length of the
// "Name: " prefix already on the first line.
func fold(used int, value string) string {
	var b strings.Builder
	width := used
	for i, word := range strings.Split(value, " ") {
		if i > 0 {
			if width+1+len(word) > 78 {
				b.WriteString("\r\n")
				width = 0
			}
			b.WriteByte(' ')
			width++
		}
		b.WriteString(word)
		width += len(word)
	}
	return b.String()
}
