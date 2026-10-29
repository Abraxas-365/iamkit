package oauthfosite

import (
	"context"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/ory/fosite"
)

func TestDecodeDoesNotOverwriteIssuanceSession(t *testing.T) {
	client := &fosite.DefaultClient{ID: "client"}
	saved := NewSession()
	saved.AccessClaims.Extra = map[string]interface{}{"permissions": []string{"read", "write"}}
	data, err := encodeRequest(&fosite.Request{ID: "request", Client: client, Session: saved})
	if err != nil {
		t.Fatal(err)
	}
	live := NewSession()
	live.AccessClaims.Extra = map[string]interface{}{"permissions": []string{"read"}}
	decoded, err := decodeRequest(data, client, live)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.GetSession() == live {
		t.Fatal("storage reused caller session")
	}
	permissions := live.AccessClaims.Extra["permissions"].([]string)
	if len(permissions) != 1 || permissions[0] != "read" {
		t.Fatal("storage overwrote current permissions")
	}
}

// repositoryOf answers FindActive from a fixed set.
type repositoryOf map[identity.ClientID]*oauth.Client

func (r repositoryOf) FindActive(_ context.Context, _ identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	if c, ok := r[id]; ok {
		return c, nil
	}
	return nil, errx.NotFound("OAuth client not found")
}

func (r repositoryOf) FindHolder(ctx context.Context, e identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	return r.FindActive(ctx, e, id)
}

// L5: a Store serves its Bound client for that client's identifiers only,
// and one Store per request never shows a request another one's client or
// redirect, however many run at once. Requests build their client from the
// same stored row (a shared Redirects slice with spare capacity), as the
// repository does for every request of one client.
func TestStoreBoundIsPerRequest(t *testing.T) {
	const n = 48
	shared := make([]string, 1, 16)
	shared[0] = "http://localhost/callback"
	ids := make([]identity.ClientID, n)
	public := make([]string, n)
	repository := repositoryOf{}
	for i := range ids {
		ids[i] = identity.NewClientID()
		public[i] = "https://c" + strconv.Itoa(i) + ".example/client.json"
		// The row an unbound lookup would find is a different client entirely.
		repository[ids[i]] = &oauth.Client{ID: ids[i], Redirects: []string{"https://registered.example/cb"}}
	}
	port := func(i int) string { return "http://localhost:" + strconv.Itoa(41000+i) + "/callback" }
	var wg sync.WaitGroup
	for round := 0; round < 4; round++ {
		for i := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				bound := &oauth.Client{ID: ids[i], Source: oauth.SourceCIMD, ExternalID: public[i], Redirects: shared}
				store := &Store{Clients: repository, Bound: bound}
				bound.AdmitRedirect(port(i))
				got, err := store.Client(context.Background(), public[i])
				if err != nil || got != bound {
					t.Errorf("client %d: bound not served: %v", i, err)
					return
				}
				// Another client's public id is not served from this store.
				if got, err = store.Client(context.Background(), public[(i+1)%n]); err == nil && got == bound {
					t.Errorf("client %d: served for %s", i, public[(i+1)%n])
				}
				for j := range ids {
					if j != i && slices.Contains(bound.Redirects, port(j)) {
						t.Errorf("client %d holds the port of %d", i, j)
						return
					}
				}
			}()
		}
	}
	wg.Wait()
	if len(shared) != 1 || slices.Contains(shared[:cap(shared)], port(0)) {
		t.Fatalf("the shared slice was written: %v", shared[:cap(shared)])
	}
}

// H-1: the row uuid of a client named by a metadata document is not its
// client_id, whether or not it is the bound client; the server's own stored
// requests still find it by row (holder).
func TestStoreRefusesExternalRowUUID(t *testing.T) {
	external := &oauth.Client{ID: identity.NewClientID(), Source: oauth.SourceCIMD, ExternalID: "https://client.example/doc"}
	store := &Store{Clients: repositoryOf{}, Bound: external}
	ctx := context.Background()
	if got, err := store.Client(ctx, external.ExternalID); err != nil || got != external {
		t.Fatalf("by URL = %v, %v", got, err)
	}
	if _, err := store.Client(ctx, external.ID.String()); err == nil {
		t.Fatal("the row uuid of an external client was accepted as a client_id")
	}
	if got, err := store.holder(ctx, external.ID.String()); err != nil || got != external {
		t.Fatalf("holder by row = %v, %v", got, err)
	}
}
