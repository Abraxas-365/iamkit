// Package ldaptest is an in-process LDAP directory for tests: simple binds
// with passwords, subtree searches with real filter matching (equality,
// presence, substrings, and, or, not), size limits and StartTLS, over a
// self-signed certificate for localhost.
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
)

// Entry is a directory entry; Password is its bind password (not an
// attribute clients can read).
type Entry struct {
	DN         string
	Password   string
	Attributes map[string][]string
}

// Server is a running directory. LDAPS serves TLS from the first byte;
// otherwise the listener is plain and clients must StartTLS.
type Server struct {
	URL string
	// CA is the PEM certificate clients must trust.
	CA string

	mu      sync.Mutex
	entries []Entry
	binds   []string
	server  *gldap.Server
	tls     *tls.Config
}

// Start runs a directory on 127.0.0.1 until the test ends. ldaps chooses
// ldaps:// or ldap:// (StartTLS).
func Start(t testing.TB, ldaps bool, entries ...Entry) *Server {
	t.Helper()
	cert, pemCA := certificate(t)
	s := &Server{CA: pemCA, entries: entries, tls: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	var err error
	if s.server, err = gldap.NewServer(); err != nil {
		t.Fatal(err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatal(err)
	}
	must(t, mux.Bind(s.bind))
	must(t, mux.Search(s.search))
	must(t, mux.ExtendedOperation(s.startTLS, gldap.ExtendedOperationStartTLS))
	must(t, s.server.Router(mux))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var opts []gldap.Option
	scheme := "ldap"
	if ldaps {
		opts, scheme = append(opts, gldap.WithTLSConfig(s.tls)), "ldaps"
	}
	go func() { _ = s.server.Run(fmt.Sprintf("127.0.0.1:%d", port), opts...) }()
	t.Cleanup(func() { _ = s.server.Stop() })
	for deadline := time.Now().Add(5 * time.Second); !s.server.Ready(); {
		if time.Now().After(deadline) {
			t.Fatal("ldaptest: directory did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.URL = fmt.Sprintf("%s://localhost:%d", scheme, port)
	return s
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Add adds an entry.
func (s *Server) Add(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
}

// Binds returns the DNs of every bind attempted so far.
func (s *Server) Binds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.binds...)
}

func (s *Server) bind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()
	m, err := r.GetSimpleBindMessage()
	if err != nil || m.AuthChoice != gldap.SimpleAuthChoice || m.Password == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.binds = append(s.binds, m.UserName)
	for _, e := range s.entries {
		if strings.EqualFold(e.DN, m.UserName) && e.Password != "" && e.Password == string(m.Password) {
			resp.SetResultCode(gldap.ResultSuccess)
			return
		}
	}
}

func (s *Server) startTLS(w *gldap.ResponseWriter, r *gldap.Request) {
	res := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	res.SetResponseName(gldap.ExtendedOperationStartTLS)
	if err := w.Write(res); err != nil {
		return
	}
	_ = r.StartTLS(s.tls)
}

func (s *Server) search(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { _ = w.Write(done) }()
	m, err := r.GetSearchMessage()
	if err != nil {
		done.SetResultCode(gldap.ResultOperationsError)
		return
	}
	packet, err := ldap.CompileFilter(m.Filter)
	if err != nil {
		done.SetResultCode(gldap.ResultOperationsError)
		return
	}
	s.mu.Lock()
	entries := append([]Entry(nil), s.entries...)
	s.mu.Unlock()
	base := strings.ToLower(m.BaseDN)
	var found []Entry
	for _, e := range entries {
		dn := strings.ToLower(e.DN)
		if (dn == base || strings.HasSuffix(dn, ","+base)) && matches(packet, e) {
			found = append(found, e)
		}
	}
	if len(found) == 0 && !s.exists(base, entries) {
		done.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	for i, e := range found {
		if m.SizeLimit > 0 && int64(i) >= m.SizeLimit {
			done.SetResultCode(gldap.ResultSizeLimitExceeded)
			return
		}
		entry := r.NewSearchResponseEntry(e.DN)
		for name, values := range e.Attributes {
			if wanted(m.Attributes, name) {
				entry.AddAttribute(name, values)
			}
		}
		if err := w.Write(entry); err != nil {
			return
		}
	}
}

// exists reports whether base names an entry or the parent of one.
func (s *Server) exists(base string, entries []Entry) bool {
	for _, e := range entries {
		dn := strings.ToLower(e.DN)
		if dn == base || strings.HasSuffix(dn, ","+base) {
			return true
		}
	}
	return false
}

func wanted(list []string, name string) bool {
	if len(list) == 0 {
		return true
	}
	for _, a := range list {
		if a == "*" || strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

func values(e Entry, name string) []string {
	for k, v := range e.Attributes {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func matches(p *ber.Packet, e Entry) bool {
	switch p.Tag {
	case ldap.FilterAnd:
		for _, c := range p.Children {
			if !matches(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range p.Children {
			if matches(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return !matches(p.Children[0], e)
	case ldap.FilterPresent:
		return len(values(e, ber.DecodeString(p.Data.Bytes()))) > 0
	case ldap.FilterEqualityMatch:
		name, want := ber.DecodeString(p.Children[0].Data.Bytes()), ber.DecodeString(p.Children[1].Data.Bytes())
		for _, v := range values(e, name) {
			if strings.EqualFold(v, want) {
				return true
			}
		}
		return false
	case ldap.FilterSubstrings:
		name := ber.DecodeString(p.Children[0].Data.Bytes())
		for _, v := range values(e, name) {
			if substrings(strings.ToLower(v), p.Children[1].Children) {
				return true
			}
		}
		return false
	}
	return false
}

func substrings(v string, parts []*ber.Packet) bool {
	for _, part := range parts {
		s := strings.ToLower(ber.DecodeString(part.Data.Bytes()))
		switch part.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(v, s) {
				return false
			}
			v = v[len(s):]
		case ldap.FilterSubstringsAny:
			i := strings.Index(v, s)
			if i < 0 {
				return false
			}
			v = v[i+len(s):]
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(v, s) {
				return false
			}
		}
	}
	return true
}

// certificate issues a self-signed certificate for localhost and 127.0.0.1.
func certificate(t testing.TB) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "ldaptest"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
