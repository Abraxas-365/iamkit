package oauthfosite

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/ory/fosite"
)

const rsaKey = `{"kty":"RSA","kid":"a","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB"}`

func TestAuthClient(t *testing.T) {
	c := authClient(&fosite.DefaultClient{ID: "x", Public: true}, identity.ClientAuth{Method: identity.AuthSecretBasic})
	if c.GetTokenEndpointAuthMethod() != identity.AuthNone {
		t.Fatal("public client must use none")
	}
	c = authClient(&fosite.DefaultClient{ID: "x"}, identity.ClientAuth{})
	if c.GetTokenEndpointAuthMethod() != identity.AuthSecretBasic || c.GetJSONWebKeys() != nil {
		t.Fatalf("default = %+v", c)
	}
	c = authClient(&fosite.DefaultClient{ID: "x"}, identity.ClientAuth{Method: identity.AuthPrivateKeyJWT, SigningAlg: "RS256", JWKS: json.RawMessage(`{"keys":[` + rsaKey + `]}`)})
	if keys := c.GetJSONWebKeys(); keys == nil || len(keys.Key("a")) != 1 || keys.Keys[0].Use != "sig" {
		t.Fatalf("keys = %+v", keys)
	}
}

func TestAssertionSubject(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"client-1"}`))
	if got := AssertionSubject("e30." + payload + ".sig"); got != "client-1" {
		t.Fatalf("sub = %q", got)
	}
	for _, bad := range []string{"", "a.b", "a.!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[]")) + ".c"} {
		if AssertionSubject(bad) != "" {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestKeyFetcher(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"keys":[` + rsaKey + `,{"kty":"RSA","kid":"enc","use":"enc","n":"AQAB","e":"AQAB"}]}`))
	}))
	defer server.Close()
	f := NewKeyFetcher(server.Client().Transport)
	set, err := f.Resolve(context.Background(), server.URL, false)
	if err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != "a" {
		t.Fatalf("set = %+v, %v", set, err)
	}
	// An unknown kid asks to ignore the cache: within the refresh interval
	// the cached set answers without a request.
	if _, err = f.Resolve(context.Background(), server.URL, true); err != nil || hits.Load() != 1 {
		t.Fatalf("hits = %d, %v", hits.Load(), err)
	}
	// The guarded default transport refuses loopback addresses.
	if _, err = NewKeyFetcher(nil).Resolve(context.Background(), server.URL, false); err == nil {
		t.Fatal("guarded fetcher reached loopback")
	}
}

func TestDigest(t *testing.T) {
	sum := sha256.Sum256([]byte("ik_svc_secret"))
	if (digest{}).Compare(context.Background(), sum[:], []byte("ik_svc_secret")) != nil {
		t.Fatal("matching secret refused")
	}
	if (digest{}).Compare(context.Background(), sum[:], []byte("other")) == nil || (digest{}).Compare(context.Background(), nil, []byte("")) == nil {
		t.Fatal("wrong secret accepted")
	}
}
