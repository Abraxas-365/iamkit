// Package fedldap checks passwords against LDAP directories (Active
// Directory, OpenLDAP…) for organization LDAP connections.
package fedldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/netx"
	"github.com/go-ldap/ldap/v3"
)

// Dialer opens the TCP connection to a directory.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Directory binds to LDAP directories over TLS (ldaps://, or ldap:// with
// StartTLS). Directories are dialed through the guarded dialer (public
// addresses only) unless their host, or host:port, is in Allowed
// (IAMKIT_LDAP_ALLOWED_HOSTS: on-premises directories on private
// networks). Dial, when set, replaces both (tests).
type Directory struct {
	Cipher  federation.Cipher
	Allowed []string
	Dial    Dialer
}

// New returns a directory client; allowed hosts are compared lowercased.
func New(cipher federation.Cipher, allowed []string, dial Dialer) Directory {
	hosts := make([]string, 0, len(allowed))
	for _, h := range allowed {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts = append(hosts, h)
		}
	}
	return Directory{Cipher: cipher, Allowed: hosts, Dial: dial}
}

// Timeout bounds a whole directory sign-in (dial, TLS, binds and search).
const Timeout = config.ExternalHTTPTimeout

func invalid() error { return errx.Unauthorized("invalid credentials") }

func unreachable() error { return errx.External("the LDAP directory could not be reached") }

// Authenticate finds the user the connection's filter names for email
// (exactly one entry) with the service account, then binds as that entry
// with the password.
func (d Directory) Authenticate(ctx context.Context, c federation.Connection, email, password string) (federation.Claims, error) {
	var out federation.Claims
	if c.Provider != federation.ProviderLDAP || password == "" {
		return out, invalid()
	}
	o := c.Options
	u, err := url.Parse(o.URL)
	server := federation.LDAPServer(o.URL)
	if err != nil || server == "" {
		return out, errx.Business("the LDAP connection has an invalid url")
	}
	address := strings.TrimPrefix(server, u.Scheme+"://")
	tlsConfig := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if o.CAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(o.CAPEM)) {
			return out, errx.Business("the LDAP connection has an invalid ca_pem")
		}
		tlsConfig.RootCAs = pool
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	raw, err := d.dial(ctx, address)
	if err != nil {
		return out, unreachable()
	}
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	var conn *ldap.Conn
	if u.Scheme == "ldaps" {
		secure := tls.Client(raw, tlsConfig)
		if err = secure.HandshakeContext(ctx); err != nil {
			raw.Close()
			return out, errx.External("the LDAP directory's TLS certificate was refused")
		}
		conn = ldap.NewConn(secure, true)
	} else {
		conn = ldap.NewConn(raw, false)
	}
	conn.Start()
	defer conn.Close()
	conn.SetTimeout(time.Until(deadline))
	if u.Scheme == "ldap" {
		// Validation requires StartTLS for ldap://: no password crosses
		// the network in clear text.
		if err = conn.StartTLS(tlsConfig); err != nil {
			return out, errx.External("the LDAP directory refused StartTLS or its certificate")
		}
	}
	if o.BindDN != "" {
		secret, err := d.Cipher.Open(c.Sealed)
		if err != nil || len(secret) == 0 {
			return out, errx.Business("the LDAP connection's bind password cannot be opened")
		}
		if err = conn.Bind(o.BindDN, string(secret)); err != nil {
			return out, errx.External("the LDAP directory refused the connection's bind_dn")
		}
	}
	local, _, _ := strings.Cut(email, "@")
	filter := o.UserFilter
	if filter == "" {
		filter = federation.DefaultUserFilter
	}
	filter = strings.NewReplacer("{email}", ldap.EscapeFilter(email), "{username}", ldap.EscapeFilter(local)).Replace(filter)
	subject, mail, name := attributes(o.Attributes)
	request := ldap.NewSearchRequest(o.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(Timeout.Seconds()), false, filter, slices.Concat(subject, mail, name), nil)
	result, err := conn.Search(request)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		// Ambiguous (several entries) or no base: nobody to bind as.
		return out, invalid()
	}
	if err != nil {
		return out, errx.External("the LDAP directory search failed")
	}
	if len(result.Entries) != 1 {
		return out, invalid()
	}
	entry := result.Entries[0]
	if err = conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return out, invalid()
		}
		return out, errx.External("the LDAP directory bind failed")
	}
	return claims(entry, subject, mail, name, email), nil
}

func (d Directory) dial(ctx context.Context, address string) (net.Conn, error) {
	if d.Dial != nil {
		return d.Dial(ctx, "tcp", address)
	}
	host, _, _ := net.SplitHostPort(address)
	if slices.Contains(d.Allowed, address) || slices.Contains(d.Allowed, host) {
		return (&net.Dialer{Timeout: Timeout}).DialContext(ctx, "tcp", address)
	}
	return netx.GuardedDialer().DialContext(ctx, "tcp", address)
}

// attributes lists the directory attributes read for the subject, email
// and name, in order of preference.
func attributes(m *federation.AttributeMapping) (subject, email, name []string) {
	subject, email, name = []string{"objectGUID", "entryUUID"}, []string{"mail", "userPrincipalName"}, []string{"displayName", "cn"}
	if m == nil {
		return
	}
	if m.Subject != "" {
		subject = []string{m.Subject}
	}
	if m.Email != "" {
		email = []string{m.Email}
	}
	if m.Name != "" {
		name = []string{m.Name}
	}
	return
}

// claims maps a directory entry. The subject is the first stable
// identifier present (binary values such as objectGUID in hex), else the
// entry's DN; the email is the first attribute holding a valid address,
// else the address the user signed in with, which the filter matched. The
// directory vouches for the email: EmailVerified stays unreported, and the
// federation service accepts only domains the organization verified.
func claims(entry *ldap.Entry, subject, email, name []string, typed string) federation.Claims {
	out := federation.Claims{Subject: strings.ToLower(entry.DN)}
	for _, a := range subject {
		if v := entry.GetEqualFoldRawAttributeValue(a); len(v) > 0 {
			out.Subject = text(v)
			break
		}
	}
	out.Email = typed
	for _, a := range email {
		if v, err := identity.Email(entry.GetEqualFoldAttributeValue(a)); err == nil {
			out.Email = v
			break
		}
	}
	for _, a := range name {
		if v := strings.TrimSpace(entry.GetEqualFoldAttributeValue(a)); v != "" {
			out.Name = v
			break
		}
	}
	return out
}

// text is a printable attribute value, or its hex encoding.
func text(v []byte) string {
	if utf8.Valid(v) && !strings.ContainsFunc(string(v), func(r rune) bool { return !unicode.IsPrint(r) }) {
		return string(v)
	}
	return hex.EncodeToString(v)
}

var _ federation.Directory = Directory{}
