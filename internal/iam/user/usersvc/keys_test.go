package usersvc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/iam/user/adapters/userkeys"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type keyRepository struct {
	user.KeyRepository
	added []user.Key
	m     user.Mutation
}

func (r *keyRepository) AddKey(_ context.Context, m user.Mutation, key user.Key) (user.Key, error) {
	r.added, r.m = append(r.added, key), m
	return key, nil
}

func TestAddKey(t *testing.T) {
	generated, _, err := userkeys.RSA{}.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// An uploaded key is stored in canonical form (use sig, no extras).
	var loose map[string]any
	_ = json.Unmarshal(generated, &loose)
	delete(loose, "use")
	loose["kid"], loose["alg"] = "mine", "RS256"
	uploaded, _ := json.Marshal(loose)
	never, bad := "never", "5m"
	user1 := identity.NewUserID()
	for name, c := range map[string]struct {
		input   user.NewKey
		private bool
		fail    string
	}{
		"generated": {private: true},
		"uploaded":  {input: user.NewKey{PublicKey: uploaded, ExpiresIn: &never}},
		"private":   {input: user.NewKey{PublicKey: json.RawMessage(`{"kty":"RSA","n":"AQAB","e":"AQAB","d":"AQAB"}`)}, fail: "private"},
		"short ttl": {input: user.NewKey{ExpiresIn: &bad}, fail: "at least 1h"},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &keyRepository{}
			out, err := NewKeys(repo, userkeys.RSA{}).AddKey(context.Background(), user.Mutation{}, user1, c.input)
			if c.fail != "" {
				if err == nil || !strings.Contains(err.Error(), c.fail) || len(repo.added) != 0 {
					t.Fatalf("err = %v", err)
				}
				return
			}
			if err != nil || len(repo.added) != 1 {
				t.Fatal(err)
			}
			if (out.PrivateKey != "") != c.private || (c.private && !strings.HasPrefix(out.PrivateKey, "-----BEGIN PRIVATE KEY-----")) {
				t.Fatalf("private key = %q", out.PrivateKey)
			}
			if repo.m.Action != user.ActionKeyAdded || repo.m.Target != out.ID.String()+"?key_id="+out.ID.String()+"&user="+user1.String() || out.User != user1 {
				t.Fatalf("mutation = %+v key = %+v", repo.m, out.Key)
			}
			if strings.Contains(string(out.PublicKey), "kid") || !strings.Contains(string(out.PublicKey), `"use":"sig"`) {
				t.Fatalf("public key = %s", out.PublicKey)
			}
			if _, err := identity.ParsePublicJWK(out.PublicKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}
