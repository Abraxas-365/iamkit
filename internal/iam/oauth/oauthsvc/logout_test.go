package oauthsvc

import (
	"context"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/oauth"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// logoutRepository fakes the two reads and the write Logout uses; the
// embedded interface panics if anything else is called.
type logoutRepository struct {
	oauth.Repository
	client *oauth.Client
	ended  []oauth.Mutation
}

func (r *logoutRepository) Environment(_ context.Context, client identity.ClientID) (identity.EnvironmentID, error) {
	if r.client == nil || client != r.client.ID {
		return identity.EnvironmentID{}, errx.NotFound("client not found")
	}
	return r.client.Environment, nil
}
func (r *logoutRepository) FindActive(_ context.Context, _ identity.EnvironmentID, _ identity.ClientID) (*oauth.Client, error) {
	return r.client, nil
}
func (r *logoutRepository) EndSession(_ context.Context, m oauth.Mutation, _ identity.UserID, _ identity.SessionID) (bool, error) {
	r.ended = append(r.ended, m)
	return true, nil
}

type fixedHints struct {
	hint oauth.IDTokenHint
	err  error
}

func (h fixedHints) Parse(context.Context, string) (oauth.IDTokenHint, error) { return h.hint, h.err }

func TestLogout(t *testing.T) {
	env, user, sid := identity.NewEnvironmentID(), identity.NewUserID(), identity.NewSessionID()
	client := &oauth.Client{ID: identity.NewClientID(), Environment: env, PostLogoutRedirects: []string{"https://app.example/bye"}}
	stranger := identity.NewClientID()
	hint := oauth.IDTokenHint{Environment: env, Subject: user, Session: sid, Clients: []string{client.ID.String()}}
	ctx := context.Background()
	service := func(h oauth.IDTokenHint, err error) (*Service, *logoutRepository) {
		repo := &logoutRepository{client: client}
		return New(repo, nil, nil, fixedHints{h, err}), repo
	}

	s, repo := service(hint, nil)
	back, environment, err := s.Logout(ctx, oauth.Logout{Hint: "h", Redirect: "https://app.example/bye", State: "a b"})
	if err != nil || back != "https://app.example/bye?state=a+b" || environment != env {
		t.Fatalf("logout = %q %v %v", back, environment, err)
	}
	if len(repo.ended) != 1 || repo.ended[0].Action != "oauth.logout" || repo.ended[0].Target != sid.String() || repo.ended[0].Actor != user.String() {
		t.Fatalf("ended = %+v", repo.ended)
	}

	// Without a redirect the hosted page shows; the session still ends.
	s, repo = service(hint, nil)
	if back, _, err = s.Logout(ctx, oauth.Logout{Hint: "h"}); err != nil || back != "" || len(repo.ended) != 1 {
		t.Fatalf("no redirect: %q %v %d", back, err, len(repo.ended))
	}

	for name, input := range map[string]oauth.Logout{
		"unregistered redirect":   {Hint: "h", Redirect: "https://evil.example/"},
		"client not in audience":  {Hint: "h", Client: stranger},
		"redirect without client": {Redirect: "https://app.example/bye"},
	} {
		s, repo = service(hint, nil)
		if _, _, err = s.Logout(ctx, input); err == nil || len(repo.ended) != 0 {
			t.Errorf("%s: err=%v ended=%d", name, err, len(repo.ended))
		}
	}
	s, repo = service(oauth.IDTokenHint{}, errx.Validation("invalid id_token_hint"))
	if _, _, err = s.Logout(ctx, oauth.Logout{Hint: "bad"}); err == nil || len(repo.ended) != 0 {
		t.Fatal("bad hint accepted")
	}

	// client_id alone may redirect to its URI; no session is named.
	s, repo = service(oauth.IDTokenHint{}, nil)
	if back, _, err = s.Logout(ctx, oauth.Logout{Client: client.ID, Redirect: "https://app.example/bye"}); err != nil || back != "https://app.example/bye" || len(repo.ended) != 0 {
		t.Fatalf("client-only logout: %q %v", back, err)
	}
	// An unknown client refuses.
	if _, _, err = s.Logout(ctx, oauth.Logout{Client: stranger, Redirect: "https://app.example/bye"}); err == nil {
		t.Fatal("unknown client accepted")
	}
	// A hint from another environment does not match the client.
	other := hint
	other.Environment = identity.NewEnvironmentID()
	s, _ = service(other, nil)
	if _, _, err = s.Logout(ctx, oauth.Logout{Hint: "h", Redirect: "https://app.example/bye"}); err == nil {
		t.Fatal("cross-environment hint accepted")
	}
}

func TestValidatePostLogout(t *testing.T) {
	if validatePostLogout([]string{"https://app.example/bye"}) != nil || validatePostLogout(nil) != nil {
		t.Fatal("valid URIs refused")
	}
	for _, bad := range []string{"http://app.example/bye", "https://app.example/bye#x", "/relative"} {
		if validatePostLogout([]string{bad}) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
