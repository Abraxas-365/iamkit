package oauthsvc

import (
	"context"
	"crypto/sha256"
	"net/url"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// txState is shared by the fake repository, its transaction and the fake
// document reader: the guard of M-5 is that nothing reads a document or
// opens another database call through the repository while a transaction
// is open.
type txState struct {
	open     bool
	violated []string
}

func (s *txState) check(what string) {
	if s.open {
		s.violated = append(s.violated, what)
	}
}

type guardedRepository struct {
	*fakeExternal
	state  *txState
	ticket oauth.Ticket
	admit  oauth.AdmissionState
	began  int
	// calls is the order of the transaction's reads (W4-9).
	calls []string
}

func (r *guardedRepository) PendingTicket(context.Context, []byte) (oauth.Ticket, error) {
	r.state.check("PendingTicket")
	return r.ticket, nil
}
func (r *guardedRepository) ExternalTargetByID(ctx context.Context, id identity.ProtectedResourceID) (oauth.ExternalTarget, error) {
	r.state.check("ExternalTargetByID")
	return r.fakeExternal.ExternalTargetByID(ctx, id)
}
func (r *guardedRepository) ExternalClientID(ctx context.Context, p identity.ProtectedResourceID, id string) (identity.ClientID, error) {
	r.state.check("ExternalClientID")
	return r.fakeExternal.ExternalClientID(ctx, p, id)
}
func (r *guardedRepository) SaveExternalClient(ctx context.Context, s oauth.ExternalSave) (identity.ClientID, error) {
	r.state.check("SaveExternalClient")
	return r.fakeExternal.SaveExternalClient(ctx, s)
}
func (r *guardedRepository) FindExternal(ctx context.Context, e identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	r.state.check("FindExternal")
	return r.fakeExternal.FindExternal(ctx, e, id)
}
func (r *guardedRepository) FindHolder(ctx context.Context, e identity.EnvironmentID, id identity.ClientID) (*oauth.Client, error) {
	r.state.check("FindHolder")
	return r.fakeExternal.FindHolder(ctx, e, id)
}
func (r *guardedRepository) RequestExternalAccess(ctx context.Context, a oauth.AccessRequest) error {
	r.state.check("RequestExternalAccess")
	return r.fakeExternal.RequestExternalAccess(ctx, a)
}
func (r *guardedRepository) Begin(context.Context) (oauth.Authorization, error) {
	r.began++
	r.state.open = true
	return &guardedTx{r}, nil
}

type guardedTx struct{ r *guardedRepository }

func (t *guardedTx) Ticket(context.Context, []byte) (oauth.Ticket, error) {
	t.r.calls = append(t.r.calls, "Ticket")
	return t.r.ticket, nil
}
func (t *guardedTx) Session(context.Context, identity.SessionID) (oauth.SessionInfo, error) {
	return oauth.SessionInfo{}, nil
}
func (t *guardedTx) Bind(context.Context, identity.SessionID, identity.ClientID, time.Duration) (time.Time, error) {
	return time.Time{}, nil
}
func (t *guardedTx) Consume(context.Context, []byte) error { return nil }
func (t *guardedTx) Admission(context.Context, identity.ClientID) (oauth.AdmissionState, error) {
	t.r.calls = append(t.r.calls, "Admission")
	return t.r.admit, nil
}
func (t *guardedTx) ApproveDevice(context.Context, identity.EnvironmentID, []byte, oauth.Login) error {
	return nil
}
func (t *guardedTx) Commit() error   { t.r.state.open = false; return nil }
func (t *guardedTx) Rollback() error { t.r.state.open = false; return nil }

type guardedDocuments struct {
	*fakeDocuments
	state *txState
}

func (d guardedDocuments) Document(ctx context.Context, u *url.URL, admit oauth.Fetch) (oauth.ExternalClient, time.Time, error) {
	d.state.check("Document")
	return d.fakeDocuments.Document(ctx, u, admit)
}

type sha256Secrets struct{ oauth.Secrets }

func (sha256Secrets) Hash(raw string) []byte { s := sha256.Sum256([]byte(raw)); return s[:] }

func newGuarded(t *testing.T, policy string, ticketClient string) (*Service, *guardedRepository, *guardedDocuments) {
	t.Helper()
	target := oauth.ExternalTarget{Environment: identity.NewEnvironmentID(), Protected: identity.NewProtectedResourceID(), ClientAdmission: policy}
	state := &txState{}
	repo := &guardedRepository{fakeExternal: &fakeExternal{target: target}, state: state}
	secrets := sha256Secrets{}
	external := ticketClient
	repo.ticket = oauth.Ticket{External: &external, Protected: target.Protected, Binding: secrets.Hash("binding"), Form: "client_id=" + url.QueryEscape(ticketClient)}
	docs := &guardedDocuments{fakeDocuments: &fakeDocuments{}, state: state}
	s := New(repo, secrets, nil, nil)
	s.SetExternalClients(docs, nil, nil)
	return s, repo, docs
}

// M-5: Complete reads the client's document and persists the client
// before it opens its transaction; inside it only the admission is read,
// on the transaction's own connection.
func TestCompleteResolvesBeforeTheTransaction(t *testing.T) {
	for name, policy := range map[string]string{"policy approved": oauth.ClientAdmissionOpen, "waiting for IT": oauth.ClientAdmissionAllowlist} {
		t.Run(name, func(t *testing.T) {
			s, repo, docs := newGuarded(t, policy, "https://claude.ai/oauth/app")
			repo.admit = oauth.AdmissionState{Admission: oauth.AdmissionApproved}
			called := false
			err := s.Complete(context.Background(), "ik_authorize_x", "binding", true, func(row oauth.Ticket, client *oauth.Client, tx oauth.Authorization) error {
				called = true
				if client == nil || !client.External() {
					t.Fatalf("client = %+v", client)
				}
				// Anything prepare does through the service happens inside
				// the transaction only on its own connection.
				return nil
			})
			if err != nil || !called {
				t.Fatalf("complete: called=%v err=%v", called, err)
			}
			if docs.asked != 1 || repo.began != 1 {
				t.Fatalf("document read %d times, %d transactions", docs.asked, repo.began)
			}
			if len(repo.state.violated) != 0 {
				t.Fatalf("used while the transaction was open: %v", repo.state.violated)
			}
		})
	}
}

// A client blocked, or whose approval ended, between the resolution and
// the transaction is refused by the transaction's own read.
func TestCompleteRechecksAdmissionInTheTransaction(t *testing.T) {
	s, repo, _ := newGuarded(t, oauth.ClientAdmissionOpen, "https://claude.ai/oauth/app")
	repo.fakeExternal.known = identity.NewClientID()
	repo.admit = oauth.AdmissionState{Admission: oauth.AdmissionBlocked}
	err := s.Complete(context.Background(), "ik_authorize_x", "binding", true, func(oauth.Ticket, *oauth.Client, oauth.Authorization) error {
		t.Fatal("prepare ran for a blocked client")
		return nil
	})
	var e *errx.Error
	if !errx.As(err, &e) || e.Code != oauth.CodeClientBlocked {
		t.Fatalf("err = %v", err)
	}
	past := time.Now().Add(-time.Minute)
	repo.admit = oauth.AdmissionState{Admission: oauth.AdmissionApproved, Expires: &past}
	err = s.Complete(context.Background(), "ik_authorize_x", "binding", true, func(oauth.Ticket, *oauth.Client, oauth.Authorization) error {
		t.Fatal("prepare ran for an expired approval")
		return nil
	})
	if !errx.As(err, &e) || e.Code != oauth.CodeClientPending {
		t.Fatalf("expired: %v", err)
	}
}

// A wrong browser binding spends nothing, reads no document and opens no
// transaction (N-3).
func TestCompleteRefusesAnotherBinding(t *testing.T) {
	s, repo, docs := newGuarded(t, oauth.ClientAdmissionOpen, "https://claude.ai/oauth/app")
	err := s.Complete(context.Background(), "ik_authorize_x", "other", true, func(oauth.Ticket, *oauth.Client, oauth.Authorization) error {
		t.Fatal("prepare ran")
		return nil
	})
	if err == nil {
		t.Fatal("another binding completed")
	}
	if docs.asked != 0 || repo.began != 0 {
		t.Fatalf("documents asked %d, transactions %d: the binding is checked first", docs.asked, repo.began)
	}
}

// M-5: asking for access reads no document; it persists the one the
// client was resolved from.
func TestRequestAccessReadsNoDocument(t *testing.T) {
	s, repo, docs := newGuarded(t, oauth.ClientAdmissionAllowlist, "https://claude.ai/oauth/app")
	client, err := s.TicketClient(context.Background(), repo.ticket)
	if err != nil {
		t.Fatal(err)
	}
	if docs.asked != 1 {
		t.Fatalf("resolution read %d", docs.asked)
	}
	if err := s.RequestAccess(context.Background(), client, identity.NewUserID(), identity.OrganizationID{}); err != nil {
		t.Fatal(err)
	}
	if docs.asked != 1 || len(repo.requests) != 1 || repo.requests[0].Document.ExternalID != "https://claude.ai/oauth/app" || repo.requests[0].Fetched.IsZero() {
		t.Fatalf("document read %d times, requests %+v", docs.asked, repo.requests)
	}
}

// W4-9: Complete locks the client's row (Admission, FOR SHARE) before the
// ticket (FOR UPDATE): the lock order of every operator change (client,
// then tickets and sessions). The other order deadlocks with a block.
func TestCompleteLocksTheClientBeforeTheTicket(t *testing.T) {
	s, repo, _ := newGuarded(t, oauth.ClientAdmissionOpen, "https://claude.ai/oauth/app")
	repo.fakeExternal.known = identity.NewClientID()
	repo.admit = oauth.AdmissionState{Admission: oauth.AdmissionApproved}
	err := s.Complete(context.Background(), "ik_authorize_x", "binding", true, func(oauth.Ticket, *oauth.Client, oauth.Authorization) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.calls) < 2 || repo.calls[0] != "Admission" || repo.calls[1] != "Ticket" {
		t.Fatalf("transaction reads %v; want Admission, then Ticket", repo.calls)
	}
}
