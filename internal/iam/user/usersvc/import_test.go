package usersvc

import (
	"context"
	"strings"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

type createRecord struct {
	input  user.Create
	hash   string
	origin string
}

type importRepository struct {
	user.Repository
	created []createRecord
	taken   map[string]bool
}

func (r *importRepository) Create(_ context.Context, _ identity.EnvironmentID, _ identity.UserID, input user.Create, hash, origin string) error {
	if r.taken[input.Email] {
		return errx.Conflict("email is taken")
	}
	r.created = append(r.created, createRecord{input, hash, origin})
	return nil
}

type hashChecker struct{ seen []string }

func (c *hashChecker) CheckHash(hash string) error {
	c.seen = append(c.seen, hash)
	if !strings.HasPrefix(hash, "$2") {
		return errx.Validation("password_hash format is not supported")
	}
	return nil
}

type plainHasher struct{}

func (plainHasher) Hash(password string) (string, error) { return "hashed:" + password, nil }

type quotaStub struct{ left int }

func (q *quotaStub) Admit(context.Context, identity.EnvironmentID, string) error {
	if q.left == 0 {
		e := errx.Business("limit reached")
		e.Code = "QUOTA_EXCEEDED"
		return e
	}
	q.left--
	return nil
}

type actionSpy struct{ requests []string }

func (a *actionSpy) Run(_ context.Context, _ identity.EnvironmentID, _ string, build func() action.Input) (action.Result, error) {
	a.requests = append(a.requests, string(build().Request))
	return action.Result{}, nil
}

func service(repo user.Repository) *Service { return New(repo, plainHasher{}, nil) }

const bcryptSample = "$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234"

func TestCreateWithPasswordHash(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	repo := &importRepository{}
	checker := &hashChecker{}
	svc := service(repo)
	svc.SetPasswordHashes(checker)
	spy := &actionSpy{}
	svc.SetActions(spy)

	_, err := svc.Create(ctx, env, user.Create{Email: "A@Example.com", Name: "A", PasswordHash: "  " + bcryptSample + " ", EmailVerified: true, Metadata: []byte(`{"plan":"pro"}`)})
	if err != nil {
		t.Fatal(err)
	}
	got := repo.created[0]
	if got.hash != bcryptSample || got.origin != "api" || got.input.PasswordHash != "" || !got.input.EmailVerified || string(got.input.Metadata) != `{"plan":"pro"}` {
		t.Fatalf("created = %+v", got)
	}
	if len(checker.seen) != 1 || checker.seen[0] != bcryptSample {
		t.Fatalf("checker saw %q", checker.seen)
	}
	if strings.Contains(spy.requests[0], bcryptSample) || strings.Contains(spy.requests[0], "password_hash") {
		t.Fatalf("action request carries the hash: %s", spy.requests[0])
	}
}

func TestCreateRejectsHash(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	base := user.Create{Email: "a@example.com", Name: "A", PasswordHash: bcryptSample}
	t.Run("no checker", func(t *testing.T) {
		_, err := service(&importRepository{}).Create(ctx, env, base)
		if err == nil || !strings.Contains(err.Error(), "password hash import is not available") {
			t.Fatalf("err = %v", err)
		}
	})
	with := func() *Service {
		s := service(&importRepository{})
		s.SetPasswordHashes(&hashChecker{})
		return s
	}
	for name, c := range map[string]struct {
		input user.Create
		fail  string
	}{
		"both":         {user.Create{Email: "a@example.com", Name: "A", Password: "a long enough one", PasswordHash: bcryptSample}, "mutually exclusive"},
		"too long":     {user.Create{Email: "a@example.com", Name: "A", PasswordHash: "$2a$" + strings.Repeat("a", 1100)}, "at most 1024"},
		"bad format":   {user.Create{Email: "a@example.com", Name: "A", PasswordHash: "plain"}, "not supported"},
		"machine hash": {user.Create{Kind: user.KindMachine, Name: "bot", PasswordHash: bcryptSample}, "machine users have no password_hash"},
		"machine mail": {user.Create{Kind: user.KindMachine, Name: "bot", EmailVerified: true}, "machine users have no email"},
		"bad metadata": {user.Create{Email: "a@example.com", Name: "A", Metadata: []byte(`[1]`)}, "metadata must be a JSON object"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := with().Create(ctx, env, c.input)
			if err == nil || !strings.Contains(err.Error(), c.fail) {
				t.Fatalf("err = %v, want %q", err, c.fail)
			}
		})
	}
}

func TestImport(t *testing.T) {
	ctx, env := context.Background(), identity.NewEnvironmentID()
	repo := &importRepository{taken: map[string]bool{"dup@example.com": true}}
	svc := service(repo)
	svc.SetPasswordHashes(&hashChecker{})
	svc.SetQuota(&quotaStub{left: 3})

	out, err := svc.Import(ctx, env, []user.Create{
		{Email: "one@example.com", Name: "One", PasswordHash: bcryptSample},
		{Email: "dup@example.com", Name: "Dup"},
		{Email: "bad", Name: "Bad"},
		{Email: "two@example.com", Name: "Two", PasswordHash: "nope"},
		{Email: "three@example.com", Name: "Three"},
		{Email: "four@example.com", Name: "Four"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Quota: one, dup and three use it up; the bad email and the bad hash fail
	// before admission; four is refused.
	if out.Created != 2 || out.Failed != 4 || len(out.Results) != 6 {
		t.Fatalf("out = %+v", out)
	}
	codes := []string{"", "CONFLICT", "VALIDATION", "VALIDATION", "", "QUOTA_EXCEEDED"}
	for i, r := range out.Results {
		if r.Index != i {
			t.Fatalf("row %d index %d", i, r.Index)
		}
		switch {
		case codes[i] == "" && (r.ID == nil || r.Error != nil):
			t.Fatalf("row %d = %+v", i, r)
		case codes[i] != "" && (r.ID != nil || r.Error == nil || r.Error.Code != codes[i]):
			t.Fatalf("row %d = %+v", i, r)
		}
	}
	for _, c := range repo.created {
		if c.origin != "import" {
			t.Fatalf("origin = %q", c.origin)
		}
	}
	if repo.created[0].hash != bcryptSample {
		t.Fatal("hash not stored")
	}
}

func TestImportBounds(t *testing.T) {
	svc := service(&importRepository{})
	if _, err := svc.Import(context.Background(), identity.NewEnvironmentID(), nil); err == nil {
		t.Fatal("empty batch accepted")
	}
	rows := make([]user.Create, user.MaxImportRows+1)
	if _, err := svc.Import(context.Background(), identity.NewEnvironmentID(), rows); err == nil {
		t.Fatal("101 rows accepted")
	}
}
