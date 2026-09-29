package authclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewOAuth(t *testing.T) {
	c := NewOAuth("http://localhost:8080/", "client", "secret")
	if c.baseURL != "http://localhost:8080" {
		t.Fatalf("trailing slash not trimmed: %s", c.baseURL)
	}
	custom := &http.Client{}
	c2 := NewOAuth("http://localhost", "c", "s", WithOAuthHTTPClient(custom))
	if c2.http != custom {
		t.Fatal("WithOAuthHTTPClient not applied")
	}
}

func TestOAuthClient(t *testing.T) {
	verifier, challenge, err := NewPKCE()
	if err != nil || len(verifier) != 43 || len(challenge) != 43 {
		t.Fatalf("PKCE %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok || id != "client" || secret != "secret" {
			t.Error("client authentication")
		}
		if r.Form.Get("code") == "bad" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		if r.URL.Path == "/oauth/revoke" {
			return
		}
		json.NewEncoder(w).Encode(OAuthTokens{TokenPair: TokenPair{AccessToken: "token"}})
	}))
	defer srv.Close()
	client := NewOAuth(srv.URL, "client", "secret")
	pair, err := client.Exchange(context.Background(), "code", "https://app.example/cb", verifier)
	if err != nil || pair.AccessToken != "token" {
		t.Fatalf("exchange %v", err)
	}
	_, err = client.Exchange(context.Background(), "bad", "https://app.example/cb", verifier)
	var custom *OAuthError
	if !errors.As(err, &custom) || custom.Code != "invalid_grant" {
		t.Fatalf("error %v", err)
	}
	if err = client.Revoke(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthOIDCEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/userinfo":
			if r.Header.Get("Authorization") != "Bearer good" {
				w.WriteHeader(401)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"sub": "u1", "email": "a@example.com", "email_verified": true, "environment_id": "e1"})
		case "/oauth/introspect":
			r.ParseForm()
			if id, secret, ok := r.BasicAuth(); !ok || id != "client" || secret != "secret" {
				t.Error("introspection client authentication")
			}
			json.NewEncoder(w).Encode(map[string]any{"active": r.Form.Get("token") == "good", "permissions": []string{"p"}})
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	client := NewOAuth(srv.URL, "client", "secret")
	info, err := client.UserInfo(ctx, "good")
	if err != nil || info.Subject != "u1" || !info.EmailVerified || info.EnvironmentID != "e1" {
		t.Fatalf("userinfo %+v %v", info, err)
	}
	var failure *OAuthError
	if _, err = client.UserInfo(ctx, "bad"); !errors.As(err, &failure) || failure.Code != "invalid_token" || failure.HTTPStatus != 401 {
		t.Fatalf("userinfo error %v", err)
	}
	got, err := client.Introspect(ctx, "good")
	if err != nil || !got.Active || len(got.Permissions) != 1 {
		t.Fatalf("introspect %+v %v", got, err)
	}
	if got, _ = client.Introspect(ctx, "bad"); got.Active {
		t.Fatal("inactive token reported active")
	}
	if _, err = NewOAuth(srv.URL, "client", "").Introspect(ctx, "good"); !errors.As(err, &failure) || failure.Code != "invalid_client" {
		t.Fatalf("public introspection %v", err)
	}
	logout := client.EndSessionURL("hint", "https://app.example/bye", "s")
	if logout != srv.URL+"/oauth/end_session?client_id=client&id_token_hint=hint&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fbye&state=s" {
		t.Fatalf("end session URL %s", logout)
	}
}

func TestClientCredentials(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var jtis []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "account" {
			t.Errorf("form = %v", r.Form)
		}
		_, _, basic := r.BasicAuth()
		switch r.Form.Get("client_assertion_type") {
		case "":
			if !basic && r.Form.Get("client_secret") != "ik_svc_x" {
				t.Error("no secret")
			}
		default:
			token, err := jwt.Parse(r.Form.Get("client_assertion"), func(tok *jwt.Token) (any, error) {
				if tok.Header["kid"] != "k1" {
					t.Errorf("kid = %v", tok.Header["kid"])
				}
				return &key.PublicKey, nil
			}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithAudience(srvURL(r)+"/oauth/token"), jwt.WithIssuer("account"), jwt.WithSubject("account"))
			if err != nil || basic {
				t.Errorf("assertion: %v", err)
			}
			jti, _ := token.Claims.(jwt.MapClaims)["jti"].(string)
			jtis = append(jtis, jti)
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "machine", "token_type": "Bearer", "expires_in": 900})
	}))
	defer srv.Close()
	for _, c := range []*OAuthClient{
		NewOAuth(srv.URL, "account", "ik_svc_x"),
		NewOAuth(srv.URL, "account", "ik_svc_x", WithClientSecretPost()),
		NewOAuth(srv.URL, "account", "", WithPrivateKeyJWT(key, "k1", "ES256")),
		NewOAuth(srv.URL, "account", "", WithPrivateKeyJWT(key, "k1", "ES256")),
	} {
		out, err := c.ClientCredentials(context.Background())
		if err != nil || out.AccessToken != "machine" {
			t.Fatalf("ClientCredentials = %+v, %v", out, err)
		}
	}
	if len(jtis) != 2 || jtis[0] == jtis[1] || jtis[0] == "" {
		t.Fatalf("jtis = %v", jtis)
	}
	if _, err = NewOAuth(srv.URL, "account", "", WithPrivateKeyJWT(key, "k1", "HS999")).ClientCredentials(context.Background()); err == nil {
		t.Fatal("unknown algorithm accepted")
	}
}

func srvURL(r *http.Request) string { return "http://" + r.Host }
