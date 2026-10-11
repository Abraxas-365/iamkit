package e2e_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/authentication/adapters/authpg"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

func b64(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }

// importedHashes are hashes of password in the formats operators import.
func importedHashes(t *testing.T, password string) map[string]string {
	t.Helper()
	salt := []byte("import-salt-0123")
	pbk, err := pbkdf2.Key(sha256.New, password, salt, 4000, 32)
	if err != nil {
		t.Fatal(err)
	}
	separator, signer := []byte("separator-bytes!"), []byte(strings.Repeat("k", 32))
	key, err := scrypt.Key([]byte(password), append(append([]byte{}, salt...), separator...), 1<<8, 4, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := make([]byte, len(signer))
	cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(sealed, signer)
	low, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"argon2id": fmt.Sprintf("$argon2id$v=19$m=1024,t=1,p=1$%s$%s", b64(salt), b64(argon2.IDKey([]byte(password), salt, 1, 1024, 1, 32))),
		"argon2i":  fmt.Sprintf("$argon2i$v=19$m=1024,t=2,p=2$%s$%s", b64(salt), b64(argon2.Key([]byte(password), salt, 2, 1024, 2, 24))),
		"pbkdf2":   fmt.Sprintf("$pbkdf2-sha256$i=4000$%s$%s", b64(salt), b64(pbk)),
		"django":   fmt.Sprintf("pbkdf2_sha256$4000$%s$%s", "import-salt-0123", base64.StdEncoding.EncodeToString(pbk)),
		"firebase": fmt.Sprintf("$firebase-scrypt$m=8,r=4$%s$%s$%s$%s", b64(salt), b64(sealed), b64(separator), b64(signer)),
		"bcrypt-4": string(low),
	}
}

type rehashState struct {
	Hash    string    `db:"password_hash"`
	Changed time.Time `db:"password_changed_at"`
}

func (e *Env) rehashState(user string) rehashState {
	e.t.Helper()
	var s rehashState
	if err := e.DB.Get(&s, `SELECT password_hash,password_changed_at FROM users WHERE id=$1`, user); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *Env) liveSessions(user string) int {
	e.t.Helper()
	return count(e.t, e.DB, `SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, user)
}

// setHash stores hash the way an import would, ahead of the test.
func (e *Env) setHash(user, hash string) {
	e.t.Helper()
	if _, err := e.DB.Exec(`UPDATE users SET password_hash=$2 WHERE id=$1`, user, hash); err != nil {
		e.t.Fatal(err)
	}
}

func (e *Env) openChallenge(user string) string {
	e.t.Helper()
	id := uuid.NewString()
	if _, err := e.DB.Exec(`INSERT INTO identity_challenges(id,environment_id,user_id,purpose,secret_hash,expires_at) VALUES($1,$2,$3,'password_reset','\x00',now()+interval '1 hour')`, id, e.EnvID, user); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *Env) challengeOpen(id string) bool {
	e.t.Helper()
	return count(e.t, e.DB, `SELECT count(*) FROM identity_challenges WHERE id=$1 AND consumed_at IS NULL`, id) == 1
}

// TestImportedPasswordsSignInAndRehash: every imported format signs in with
// its password only, and the sign-in replaces it by IAMKit's bcrypt without
// touching what a password change would: sessions, emailed challenges,
// password_changed_at, events.
func TestImportedPasswordsSignInAndRehash(t *testing.T) {
	e := newEnv(t)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	current := e.rehashState(bob).Hash

	for name, hash := range importedHashes(t, e.Pass) {
		t.Run(name, func(t *testing.T) {
			e.setHash(bob, hash)
			before := e.rehashState(bob)
			challenge := e.openChallenge(bob)
			events := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='user.password_changed'`, e.EnvID)

			// Wrong password: refused, hash untouched.
			e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass+"x"), 401)
			if got := e.rehashState(bob).Hash; got != hash {
				t.Fatalf("wrong password changed the hash to %q", got)
			}

			e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200)
			after := e.rehashState(bob)
			if after.Hash == hash || !strings.HasPrefix(after.Hash, "$2") || bcrypt.CompareHashAndPassword([]byte(after.Hash), []byte(e.Pass)) != nil {
				t.Fatalf("hash after sign-in = %q", after.Hash)
			}
			if cost, _ := bcrypt.Cost([]byte(after.Hash)); cost < 12 {
				t.Fatalf("rehash cost = %d", cost)
			}
			if !after.Changed.Equal(before.Changed) {
				t.Fatalf("password_changed_at moved: %v → %v", before.Changed, after.Changed)
			}
			if !e.challengeOpen(challenge) {
				t.Fatal("rehash spent an emailed challenge")
			}
			if n := count(t, e.DB, `SELECT count(*) FROM events WHERE environment_id=$1 AND type='user.password_changed'`, e.EnvID); n != events {
				t.Fatalf("user.password_changed events %d → %d", events, n)
			}

			// The new hash is what later sign-ins use, and it is not rewritten.
			e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200)
			if got := e.rehashState(bob).Hash; got != after.Hash {
				t.Fatal("a current hash was rewritten")
			}
		})
	}
	if current == "" {
		t.Fatal("fixture")
	}
}

// TestRehashKeepsSessions: signing in with a stale hash ends nobody's
// sessions, while a real password change (any other write of password_hash)
// still does.
func TestRehashKeepsSessions(t *testing.T) {
	e := newEnv(t)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200)
	if e.liveSessions(bob) != 1 {
		t.Fatal("no live session")
	}
	// Put a stale hash behind the live session the way the rehash writes: the
	// production statement, flag on.
	stale := importedHashes(t, e.Pass)["argon2id"]
	e.rehashTx(bob, e.rehashState(bob).Hash, stale)
	if got := e.rehashState(bob).Hash; got != stale {
		t.Fatalf("RehashPassword wrote %q", got)
	}
	if e.liveSessions(bob) != 1 {
		t.Fatal("RehashPassword ended a session")
	}
	// A sign-in with the stale hash adds its own session; the first stays.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200)
	if n := e.liveSessions(bob); n != 2 {
		t.Fatalf("live sessions after a rehash sign-in = %d, want 2", n)
	}

	// Control: a plain password_hash write (reset, operator, SQL) still
	// revokes sessions and spends challenges.
	challenge := e.openChallenge(bob)
	e.setHash(bob, "$2b$12$"+strings.Repeat("a", 53))
	if n := e.liveSessions(bob); n != 0 {
		t.Fatalf("a password change left %d live sessions", n)
	}
	if e.challengeOpen(challenge) {
		t.Fatal("a password change left an open challenge")
	}
}

// rehashTx runs authpg's RehashPassword in its own transaction.
func (e *Env) rehashTx(user, old, hash string) {
	e.t.Helper()
	tx, err := e.DB.Beginx()
	if err != nil {
		e.t.Fatal(err)
	}
	defer tx.Rollback()
	envID, userID := mustEnvironment(e.t, e.EnvID), mustUser(e.t, user)
	if err = authpg.Wrap(tx).RehashPassword(e.ctx(), envID, userID, old, hash); err != nil {
		e.t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		e.t.Fatal(err)
	}
}

// TestRehashIsScoped: the rehash writes only while the stored hash is still
// the one that matched, and its trigger bypass ends with the statement.
func TestRehashIsScoped(t *testing.T) {
	e := newEnv(t)
	bob := e.User("Bob", "bob@example.com")
	e.Join(e.Org, bob)
	e.Grant(e.Org, bob, e.Res, "invoices:read")
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200)
	original := e.rehashState(bob).Hash

	// Another writer changed the hash since the compare: nothing is written.
	e.rehashTx(bob, "not-the-stored-hash", "$2b$12$"+strings.Repeat("b", 53))
	if got := e.rehashState(bob).Hash; got != original {
		t.Fatalf("rehash against a changed hash wrote %q", got)
	}

	// The bypass is for that statement only: a password change later in the
	// same transaction still fires the triggers.
	tx, err := e.DB.Beginx()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	envID, userID := mustEnvironment(t, e.EnvID), mustUser(t, bob)
	stale := importedHashes(t, e.Pass)["pbkdf2"]
	if err = authpg.Wrap(tx).RehashPassword(e.ctx(), envID, userID, original, stale); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE users SET password_hash=$2 WHERE id=$1`, bob, "$2b$12$"+strings.Repeat("c", 53)); err != nil {
		t.Fatal(err)
	}
	var live int
	if err = tx.Get(&live, `SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, bob); err != nil || live != 0 {
		t.Fatalf("password change after a rehash left %d sessions (%v)", live, err)
	}

	tx.Rollback()

	// Rehash combined with another change (email) still revokes: only a
	// password_hash-only update is exempt.
	e.Must("POST", "/identity/v1/login", "", e.LoginBody("bob@example.com", e.Pass), 200)
	challenge := e.openChallenge(bob)
	tx2, err := e.DB.Beginx()
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback()
	if _, err = tx2.Exec(`SELECT set_config('iamkit.password_rehash','on',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx2.Exec(`UPDATE users SET password_hash=$2, email='bob2@example.com' WHERE id=$1`, bob, stale); err != nil {
		t.Fatal(err)
	}
	if err = tx2.Get(&live, `SELECT count(*) FROM sessions WHERE user_id=$1 AND revoked_at IS NULL`, bob); err != nil || live != 0 {
		t.Fatalf("hash+email change under the flag left %d sessions (%v)", live, err)
	}
	if err = tx2.Commit(); err != nil {
		t.Fatal(err)
	}
	if e.challengeOpen(challenge) {
		t.Fatal("hash+email change under the flag left a challenge open")
	}
}

// TestHostedSignInRehashes: the hosted password page (Authenticator
// .VerifyPassword) replaces a stale hash too.
func TestHostedSignInRehashes(t *testing.T) {
	e := newEnv(t)
	client := e.hostedClient()
	hash := importedHashes(t, e.Pass)["django"]
	e.setHash(e.Alice, hash)
	before := e.rehashState(e.Alice)

	b := e.browser()
	tk := b.authorize(client).field("ticket")
	if r := b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {"wrong password!!"}}); r.Status != 401 {
		t.Fatalf("wrong password: %d", r.Status)
	}
	if got := e.rehashState(e.Alice).Hash; got != hash {
		t.Fatal("wrong password changed the hash")
	}
	b.exchange(client, b.post("/hosted/login/password", url.Values{"ticket": {tk}, "email": {e.AliceEmail}, "password": {e.Pass}}))
	after := e.rehashState(e.Alice)
	if !strings.HasPrefix(after.Hash, "$2") || bcrypt.CompareHashAndPassword([]byte(after.Hash), []byte(e.Pass)) != nil || !after.Changed.Equal(before.Changed) {
		t.Fatalf("hosted sign-in rehash: %+v", after)
	}
}

// TestPasswordOverCapHashIsRefusedAtSignIn: a stored hash asking for more than the
// caps is a plain credential failure, never computed.
func TestPasswordOverCapHashIsRefusedAtSignIn(t *testing.T) {
	e := newEnv(t)
	salt := []byte("import-salt-0123")
	sum := make([]byte, 32)
	for name, hash := range map[string]string{
		"argon2 memory": fmt.Sprintf("$argon2id$v=19$m=4194304,t=1,p=1$%s$%s", b64(salt), b64(sum)),
		"pbkdf2 rounds": fmt.Sprintf("$pbkdf2-sha256$i=999999999$%s$%s", b64(salt), b64(sum)),
		"firebase":      fmt.Sprintf("$firebase-scrypt$m=15,r=16$%s$%s$%s$%s", b64(salt), b64(sum), b64(salt), b64(sum)),
		"unsupported":   "5f4dcc3b5aa765d61d8327deb882cf99",
	} {
		e.setHash(e.Alice, hash)
		start := time.Now()
		e.Must("POST", "/identity/v1/login", "", e.LoginBody(e.AliceEmail, e.Pass), 401)
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("%s: refusing took %v", name, d)
		}
		if got := e.rehashState(e.Alice).Hash; got != hash {
			t.Fatalf("%s: hash rewritten", name)
		}
	}
}

func mustEnvironment(t *testing.T, id string) identity.EnvironmentID {
	t.Helper()
	v, err := identity.ParseEnvironmentID(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustUser(t *testing.T, id string) identity.UserID {
	t.Helper()
	v, err := identity.ParseUserID(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (e *Env) ctx() context.Context { return context.Background() }
