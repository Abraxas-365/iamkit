package fedoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/federation"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP plays Google, Microsoft, GitHub and Apple: a rewriting transport
// sends every provider host to one TLS server, which routes by the
// original host.
type fakeIdP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	// claims is the next ID token's claims (iss/aud/exp filled in).
	claims jwt.MapClaims
	// issuer is the next ID token's issuer; for Microsoft it is per tenant.
	issuer string
	// form is the last token request.
	form url.Values
	// secret is the client secret of the last token request (basic auth or
	// form).
	secret string
	// apple verifies Apple client secrets.
	apple *ecdsa.PublicKey
	// emails is GitHub's /user/emails answer.
	emails string
}

func newIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

type rewrite struct {
	target *url.URL
	base   http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	out := req.Clone(req.Context())
	out.Host = req.URL.Host
	out.URL.Scheme, out.URL.Host = r.target.Scheme, r.target.Host
	return r.base.RoundTrip(out)
}

func (f *fakeIdP) provider() Provider {
	target, _ := url.Parse(f.server.URL)
	return Provider{Issuer: "https://iam.example", Cipher: plainCipher{}, Guarded: rewrite{target: target, base: f.server.Client().Transport}}
}

func (f *fakeIdP) serve(w http.ResponseWriter, r *http.Request) {
	host, path := r.Host, r.URL.Path
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(path, "/.well-known/openid-configuration"):
		issuer := "https://" + host + strings.TrimSuffix(path, "/.well-known/openid-configuration")
		if host == "login.microsoftonline.com" {
			// Microsoft's multi-tenant metadata names a templated issuer.
			issuer = "https://login.microsoftonline.com/{tenantid}/v2.0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": "https://" + host + "/authorize", "token_endpoint": "https://" + host + "/token",
			"jwks_uri": "https://" + host + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case path == "/jwks":
		n := base64.RawURLEncoding.EncodeToString(f.key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": n, "e": e}}})
	case path == "/token" || path == "/login/oauth/access_token":
		_ = r.ParseForm()
		f.form = r.PostForm
		if f.apple != nil && !f.appleSecretValid(r.PostForm.Get("client_secret")) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		out := map[string]any{"access_token": "at", "token_type": "bearer"}
		client := r.PostForm.Get("client_id")
		f.secret = r.PostForm.Get("client_secret")
		if user, password, ok := r.BasicAuth(); ok {
			client, _ = url.QueryUnescape(user)
			f.secret, _ = url.QueryUnescape(password)
		}
		if host != "github.com" {
			out["id_token"] = f.idToken(client)
		}
		_ = json.NewEncoder(w).Encode(out)
	case host == "api.github.com" && path == "/user":
		if r.Header.Get("Authorization") != "Bearer at" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"id":583231,"login":"octocat","name":""}`))
	case host == "api.github.com" && path == "/user/emails":
		_, _ = w.Write([]byte(f.emails))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeIdP) idToken(client string) string {
	claims := jwt.MapClaims{"iss": f.issuer, "aud": client, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
	for k, v := range f.claims {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "k1"
	raw, err := token.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fakeIdP) appleSecretValid(raw string) bool {
	token, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return f.apple, nil }, jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience("https://appleid.apple.com"), jwt.WithIssuer("TEAM123456"))
	if err != nil || token.Header["kid"] != "KEY1234567" {
		return false
	}
	sub, _ := token.Claims.GetSubject()
	return sub == "com.example.web"
}

func connection(provider string, o federation.Options, secret string) federation.Connection {
	c := federation.ConnectionInput{Name: provider, Provider: provider, Options: o, Client: "client-1", ClientSecret: secret}.Connection(identity.NewEnvironmentID())
	c.Sealed = secret
	return c
}

func authorizeURL(t *testing.T, p Provider, c federation.Connection) url.Values {
	t.Helper()
	raw, err := p.Authorize(context.Background(), c, "state-1", "nonce-1", "verifier-verifier-verifier-verifier-verifier1")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	return u.Query()
}

func TestGoogle(t *testing.T) {
	idp := newIdP(t)
	c := connection(federation.ProviderGoogle, federation.Options{}, "secret")
	q := authorizeURL(t, idp.provider(), c)
	if q.Get("nonce") != "nonce-1" || q.Get("code_challenge") == "" || !strings.Contains(q.Get("scope"), "email") {
		t.Fatalf("authorize: %v", q)
	}
	idp.issuer = "https://accounts.google.com"
	idp.claims = jwt.MapClaims{"sub": "g-1", "nonce": "nonce-1", "email": "ann@gmail.com", "email_verified": true, "name": "Ann"}
	claims, err := idp.provider().Verify(context.Background(), c, "code", "nonce-1", "verifier-verifier-verifier-verifier-verifier1")
	if err != nil || claims.Subject != "g-1" || claims.EmailVerified == nil || !*claims.EmailVerified {
		t.Fatalf("verify: %+v %v", claims, err)
	}
	if idp.form.Get("code_verifier") == "" {
		t.Fatal("PKCE verifier not sent")
	}
	idp.issuer = "https://evil.example"
	if _, err = idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v"); err == nil {
		t.Fatal("wrong issuer accepted")
	}
}

func TestGoogleHostedDomain(t *testing.T) {
	idp := newIdP(t)
	c := connection(federation.ProviderGoogle, federation.Options{}, "secret")
	idp.issuer = "https://accounts.google.com"
	idp.claims = jwt.MapClaims{"sub": "g-1", "nonce": "nonce-1", "email": "ann@acme.com", "email_verified": true, "hd": "acme.com"}
	claims, err := idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v")
	if err != nil || claims.HostedDomain != "acme.com" {
		t.Fatalf("workspace account: %+v %v", claims, err)
	}
	delete(idp.claims, "hd")
	if claims, err = idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v"); err != nil || claims.HostedDomain != "" {
		t.Fatalf("personal account: %+v %v", claims, err)
	}
	// A connection restricted to Workspace domains refuses personal accounts
	// and other domains.
	restricted := connection(federation.ProviderGoogle, federation.Options{Domains: []string{"acme.com"}}, "secret")
	if _, err = idp.provider().Verify(context.Background(), restricted, "code", "nonce-1", "v"); err == nil {
		t.Fatal("personal account accepted by a Workspace connection")
	}
	idp.claims["hd"] = "other.com"
	if _, err = idp.provider().Verify(context.Background(), restricted, "code", "nonce-1", "v"); err == nil {
		t.Fatal("other Workspace domain accepted")
	}
	idp.claims["hd"] = "acme.com"
	if claims, err = idp.provider().Verify(context.Background(), restricted, "code", "nonce-1", "v"); err != nil || claims.HostedDomain != "acme.com" {
		t.Fatalf("allowed Workspace domain: %+v %v", claims, err)
	}
	// Google may send its issuer without the scheme; the identity keeps the
	// configured issuer, so it is one account either way.
	idp.issuer = "accounts.google.com"
	if claims, err = idp.provider().Verify(context.Background(), restricted, "code", "nonce-1", "v"); err != nil || claims.Issuer != "https://accounts.google.com" {
		t.Fatalf("scheme-less issuer: %+v %v", claims, err)
	}
	idp.issuer = "https://accounts.google.com"
	// Only Google's hd is meaningful; another issuer's claim is ignored.
	o := connection(federation.ProviderOIDC, federation.Options{}, "secret")
	o.Issuer = "https://idp.example"
	idp.issuer, idp.claims["hd"] = o.Issuer, "acme.com"
	if claims, err = idp.provider().Verify(context.Background(), o, "code", "nonce-1", "v"); err != nil || claims.HostedDomain != "" {
		t.Fatalf("generic oidc: %+v %v", claims, err)
	}
}

// A deployment-configured provider (operator single sign-on) takes its
// secret and redirect URI from the Provider rather than the connection, and
// reaches the IdP through Transport rather than the guarded transport.
func TestDeploymentProvider(t *testing.T) {
	idp := newIdP(t)
	target, _ := url.Parse(idp.server.URL)
	p := Provider{
		Issuer:    "https://iam.example",
		Redirect:  "https://iam.example/management/v1/sso/callback",
		Secret:    "deployment-secret",
		Transport: rewrite{target: target, base: idp.server.Client().Transport},
		Guarded:   failing{},
	}
	// Sealed is set to prove Secret wins over it and over the guarded path.
	c := federation.Connection{Provider: federation.ProviderGoogle, Issuer: federation.Preset(federation.ProviderGoogle, federation.Options{}), Client: "client-1", Sealed: "ignored"}
	if p.Callback() != p.Redirect {
		t.Fatalf("callback: %s", p.Callback())
	}
	if q := authorizeURL(t, p, c); q.Get("redirect_uri") != p.Redirect {
		t.Fatalf("redirect_uri: %v", q)
	}
	idp.issuer = "https://accounts.google.com"
	idp.claims = jwt.MapClaims{"sub": "g-1", "nonce": "nonce-1", "email": "ann@acme.com", "email_verified": true}
	if claims, err := p.Verify(context.Background(), c, "code", "nonce-1", "v"); err != nil || claims.Issuer != "https://accounts.google.com" {
		t.Fatalf("verify: %+v %v", claims, err)
	}
	if idp.secret != "deployment-secret" || idp.form.Get("redirect_uri") != p.Redirect {
		t.Fatalf("token request: secret %q form %v", idp.secret, idp.form)
	}
	if got := (Provider{Issuer: "https://iam.example"}).Callback(); got != "https://iam.example/identity/v1/federation/callback" {
		t.Fatalf("default callback changed: %s", got)
	}

	// Microsoft as operator SSO builds it: "organizations" restricted to a
	// tenant list. The identity's issuer is the verified per-tenant one;
	// other tenants are refused and a work email is not proof of ownership.
	const work, other = "11111111-2222-3333-4444-555555555555", "99999999-2222-3333-4444-555555555555"
	mo := federation.Options{Tenant: federation.TenantOrganizations, Tenants: []string{work}}.Normalized()
	m := federation.Connection{Provider: federation.ProviderMicrosoft, Issuer: federation.Preset(federation.ProviderMicrosoft, mo), Client: "client-1", Options: mo}
	idp.issuer = MicrosoftIssuer(work)
	idp.claims = jwt.MapClaims{"sub": "m-1", "nonce": "nonce-1", "tid": work, "email": "ann@acme.com"}
	claims, err := p.Verify(context.Background(), m, "code", "nonce-1", "v")
	if err != nil || claims.Issuer != MicrosoftIssuer(work) || claims.EmailVerified == nil || *claims.EmailVerified {
		t.Fatalf("microsoft: %+v %v", claims, err)
	}
	idp.issuer, idp.claims["tid"] = MicrosoftIssuer(other), other
	if _, err = p.Verify(context.Background(), m, "code", "nonce-1", "v"); err == nil {
		t.Fatal("tenant outside the list accepted")
	}
}

type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("guarded transport used")
}

func TestMicrosoftMultiTenant(t *testing.T) {
	const work = "11111111-2222-3333-4444-555555555555"
	idp := newIdP(t)
	c := connection(federation.ProviderMicrosoft, federation.Options{Tenant: federation.TenantCommon}, "secret")
	verify := func() (federation.Claims, error) {
		return idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v")
	}
	// A personal account: its email is verified.
	idp.issuer = MicrosoftIssuer(federation.ConsumerTenant)
	idp.claims = jwt.MapClaims{"sub": "m-1", "nonce": "nonce-1", "tid": federation.ConsumerTenant, "email": "ann@outlook.com"}
	claims, err := verify()
	if err != nil || claims.EmailVerified == nil || !*claims.EmailVerified {
		t.Fatalf("consumer: %+v %v", claims, err)
	}
	// A work account without xms_edov: the tenant's email is not proof.
	idp.issuer = MicrosoftIssuer(work)
	idp.claims = jwt.MapClaims{"sub": "m-2", "nonce": "nonce-1", "tid": work, "email": "ann@contoso.com"}
	if claims, err = verify(); err != nil || claims.EmailVerified == nil || *claims.EmailVerified {
		t.Fatalf("work without edov: %+v %v", claims, err)
	}
	idp.claims["xms_edov"] = true
	if claims, err = verify(); err != nil || !*claims.EmailVerified {
		t.Fatalf("work with edov: %+v %v", claims, err)
	}
	// The issuer must be the token's own tenant.
	idp.issuer = MicrosoftIssuer(federation.ConsumerTenant)
	if _, err = verify(); err == nil {
		t.Fatal("issuer of another tenant accepted")
	}
	// A tenant allow-list refuses other tenants.
	idp.issuer = MicrosoftIssuer(work)
	c.Options.Tenants = []string{"99999999-2222-3333-4444-555555555555"}
	if _, err = verify(); err == nil {
		t.Fatal("tenant outside the allow-list accepted")
	}
}

func TestMicrosoftSingleTenant(t *testing.T) {
	const work = "11111111-2222-3333-4444-555555555555"
	idp := newIdP(t)
	c := connection(federation.ProviderMicrosoft, federation.Options{Tenant: work}, "secret")
	idp.issuer = MicrosoftIssuer(work)
	idp.claims = jwt.MapClaims{"sub": "m-1", "nonce": "nonce-1", "tid": work, "email": "ann@contoso.com"}
	claims, err := idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v")
	if err != nil || claims.EmailVerified != nil {
		t.Fatalf("single tenant email is unknown, not false: %+v %v", claims, err)
	}
}

func TestGitHub(t *testing.T) {
	idp := newIdP(t)
	c := connection(federation.ProviderGitHub, federation.Options{}, "secret")
	q := authorizeURL(t, idp.provider(), c)
	if q.Get("nonce") != "" || q.Get("scope") != "read:user user:email" || q.Get("code_challenge") == "" {
		t.Fatalf("authorize: %v", q)
	}
	idp.emails = `[{"email":"old@example.com","primary":false,"verified":true},{"email":"octo@example.com","primary":true,"verified":true}]`
	claims, err := idp.provider().Verify(context.Background(), c, "code", "", "v")
	if err != nil || claims.Subject != "583231" || claims.Email != "octo@example.com" || !*claims.EmailVerified || claims.Name != "octocat" {
		t.Fatalf("verify: %+v %v", claims, err)
	}
	if idp.form.Get("client_secret") != "secret" {
		t.Fatal("GitHub takes the secret in the form")
	}
	idp.emails = `[{"email":"octo@example.com","primary":true,"verified":false}]`
	if claims, err = idp.provider().Verify(context.Background(), c, "code", "", "v"); err != nil || *claims.EmailVerified {
		t.Fatalf("unverified primary: %+v %v", claims, err)
	}
}

func TestApple(t *testing.T) {
	idp := newIdP(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	secret := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	idp.apple = &key.PublicKey
	c := federation.ConnectionInput{Name: "Apple", Provider: federation.ProviderApple, Options: federation.Options{Team: "TEAM123456", Key: "KEY1234567"}, Client: "com.example.web", ClientSecret: secret}.Connection(identity.NewEnvironmentID())
	c.Sealed = secret
	q := authorizeURL(t, idp.provider(), c)
	if q.Get("response_mode") != "form_post" || q.Get("nonce") != "nonce-1" || q.Get("code_challenge") != "" {
		t.Fatalf("authorize: %v", q)
	}
	idp.issuer = "https://appleid.apple.com"
	idp.claims = jwt.MapClaims{"sub": "001.abc", "nonce": "nonce-1", "email": "x@privaterelay.appleid.com", "email_verified": "true"}
	claims, err := idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v")
	if err != nil || claims.Subject != "001.abc" || !*claims.EmailVerified {
		t.Fatalf("verify: %+v %v", claims, err)
	}
	if idp.form.Get("code_verifier") != "" {
		t.Fatal("Apple does not take a PKCE verifier")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp.apple = &other.PublicKey
	if _, err = idp.provider().Verify(context.Background(), c, "code", "nonce-1", "v"); err == nil {
		t.Fatal("secret signed with another key accepted")
	}
}
