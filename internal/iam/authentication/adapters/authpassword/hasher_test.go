package authpassword

import (
	"crypto/aes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

const password = "correct horse"

// Vectors computed with other implementations (the argon2 reference CLI,
// Python hashlib/cryptography, htpasswd) for the password above.
var vectors = []struct {
	name, hash string
	stale      bool
}{
	{"bcrypt 2y cost 4", "$2y$04$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.uy", true},
	{"bcrypt 2y cost 4 other salt", "$2y$04$aqL7fkeolG2sDgZBmlm27.Jmoyq9uzrsz2b.juAeuRzlKPOWdAAT2", true},
	{"argon2id", "$argon2id$v=19$m=8192,t=1,p=1$c29tZXNhbHQxMg$iQ4t5GKRkkD/JhUwwdqrvqD8mebt4Ou067fG/iJSRBk", true},
	{"argon2i 24-byte hash", "$argon2i$v=19$m=8192,t=2,p=2$c29tZXNhbHQxMg$qYGx1v4a9m1sOp0xntOE3vPfCDJdwxEu", true},
	{"pbkdf2 phc sha1", "$pbkdf2-sha1$i=1000$c2FsdHNhbHQxMg$D2gj+B2zLE6XhLP/HRNZnOzxK9k", true},
	{"pbkdf2 phc sha256 padded", "$pbkdf2-sha256$i=1000$c2FsdHNhbHQxMg==$C0j01VXL8UGUSYjMXpWw3FIox97CRvbCLLJgzTGzcnM=", true},
	{"pbkdf2 phc sha512", "$pbkdf2-sha512$i=1000$c2FsdHNhbHQxMg$H4M87+BRFMN6IHJa5UaLK2Zj8HnSs+U+2NRDL7b1TYY4xmn9JNE9l1gVrWP1UD1zxRG7NLCP6oaT2aBO+KmYxg", true},
	{"pbkdf2 passlib sha1", "$pbkdf2-sha1$1000$c2FsdHNhbHQxMg$D2gj.B2zLE6XhLP/HRNZnOzxK9k", true},
	{"pbkdf2 passlib sha512", "$pbkdf2-sha512$1000$c2FsdHNhbHQxMg$H4M87.BRFMN6IHJa5UaLK2Zj8HnSs.U.2NRDL7b1TYY4xmn9JNE9l1gVrWP1UD1zxRG7NLCP6oaT2aBO.KmYxg", true},
	{"django sha256", "pbkdf2_sha256$1000$saltsalt12$C0j01VXL8UGUSYjMXpWw3FIox97CRvbCLLJgzTGzcnM=", true},
	{"django sha1", "pbkdf2_sha1$1000$saltsalt12$D2gj+B2zLE6XhLP/HRNZnOzxK9k=", true},
}

func TestCompareVectors(t *testing.T) {
	h := Hasher{}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			if err := h.CheckHash(v.hash); err != nil {
				t.Fatalf("CheckHash: %v", err)
			}
			matches, stale := h.Compare(v.hash, password)
			if !matches || stale != v.stale {
				t.Fatalf("Compare = %v, %v", matches, stale)
			}
			if matches, stale = h.Compare(v.hash, password+"!"); matches || stale {
				t.Fatalf("wrong password: Compare = %v, %v", matches, stale)
			}
		})
	}
}

func TestBcryptStale(t *testing.T) {
	h := Hasher{}
	cost := func(c int) string {
		b, err := bcrypt.GenerateFromPassword([]byte(password), c)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	current, err := h.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if m, s := h.Compare(current, password); !m || s {
		t.Fatalf("current-cost bcrypt: %v, %v", m, s)
	}
	if m, s := h.Compare(cost(4), password); !m || !s {
		t.Fatalf("low-cost bcrypt: %v, %v", m, s)
	}
	if m, s := h.Compare(cost(13), password); !m || !s {
		t.Fatalf("higher-cost bcrypt is stale too: %v, %v", m, s)
	}
	// $2b$ and $2a$ at the current cost are not stale; $2y$ is.
	if m, s := h.Compare("$2a$"+current[4:], password); !m || s {
		t.Fatalf("2a: %v, %v", m, s)
	}
	if m, s := h.Compare("$2y$"+current[4:], password); !m || !s {
		t.Fatalf("2y: %v, %v", m, s)
	}
}

// Firebase's published sample (firebase/scrypt README).
const firebaseSample = "$firebase-scrypt$m=14,r=8$42xEC+ixf3L2lw==$lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==$Bw==$jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="

func TestFirebaseSample(t *testing.T) {
	h := Hasher{}
	if err := h.CheckHash(firebaseSample); err != nil {
		t.Fatal(err)
	}
	if m, s := h.Compare(firebaseSample, "user1password"); !m || !s {
		t.Fatalf("published sample: %v, %v", m, s)
	}
	if m, _ := h.Compare(firebaseSample, "user2password"); m {
		t.Fatal("wrong password matched")
	}
}

// firebaseHash is firebase/scrypt written out again with crypto/aes and CTR
// by hand (a counter block incremented per 16 bytes), as an independent
// check of verifyFirebase on parameters other than the sample's.
func firebaseHash(t *testing.T, password string, salt, separator, signer []byte, memCost, rounds int) string {
	t.Helper()
	key, err := scrypt.Key([]byte(password), append(append([]byte{}, salt...), separator...), 1<<memCost, rounds, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	var counter [16]byte
	out := make([]byte, 0, len(signer))
	for i := 0; i < len(signer); i += 16 {
		var stream [16]byte
		block.Encrypt(stream[:], counter[:])
		for j := 0; j < 16 && i+j < len(signer); j++ {
			out = append(out, signer[i+j]^stream[j])
		}
		for k := 15; k >= 0; k-- {
			if counter[k]++; counter[k] != 0 {
				break
			}
		}
	}
	e := base64.StdEncoding
	return fmt.Sprintf("$firebase-scrypt$m=%d,r=%d$%s$%s$%s$%s", memCost, rounds, e.EncodeToString(salt), e.EncodeToString(out), e.EncodeToString(separator), e.EncodeToString(signer))
}

func TestFirebaseIndependent(t *testing.T) {
	h := Hasher{}
	signer := []byte(strings.Repeat("0123456789abcdef", 4)) // 64 bytes, several CTR blocks
	for _, c := range []struct{ m, r, signer int }{{4, 2, 64}, {10, 8, 64}, {1, 1, 32}, {12, 3, 20}} {
		hash := firebaseHash(t, "hunter2-pass", []byte("salty-salt-16byt"), []byte("sep-sep-sep"), signer[:c.signer], c.m, c.r)
		if err := h.CheckHash(hash); err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if m, s := h.Compare(hash, "hunter2-pass"); !m || !s {
			t.Fatalf("%v: match %v stale %v", c, m, s)
		}
		if m, _ := h.Compare(hash, "hunter2-pasS"); m {
			t.Fatalf("%v: wrong password matched", c)
		}
	}
}

func TestCheckHashRefusals(t *testing.T) {
	const (
		unsupported = "password_hash format is not supported"
		cost        = "password_hash parameters exceed the allowed cost"
		malformed   = "password_hash is malformed"
	)
	salt := base64.RawStdEncoding.EncodeToString([]byte("saltsalt"))
	sum := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	argon := func(params string) string { return "$argon2id$v=19$" + params + "$" + salt + "$" + sum }
	pbkdf := func(i string) string { return "$pbkdf2-sha256$i=" + i + "$" + salt + "$" + sum }
	fire := func(params string) string {
		return "$firebase-scrypt$" + params + "$" + salt + "$" + sum + "$Bw==$" + sum
	}
	for hash, want := range map[string]string{
		"":                                 unsupported,
		"plaintext":                        unsupported,
		"5f4dcc3b5aa765d61d8327deb882cf99": unsupported, // md5
		"{SSHA}Zm9vYmFy":                   unsupported,
		"sha1$salt$abcdef":                 unsupported,
		"$scrypt$ln=14,r=8,p=1$" + salt + "$" + sum:                               unsupported,
		"$pbkdf2-sha384$i=1000$" + salt + "$" + sum:                               unsupported,
		"$bcrypt-sha256$v=2,t=2b,r=12$" + salt + "$" + sum:                        unsupported,
		"pbkdf2_sha512$1000$saltsalt$" + sum:                                      unsupported,
		"$argon2d$v=19$m=1024,t=1,p=1$" + salt + "$" + sum:                        unsupported,
		"$argon2id$v=16$m=1024,t=1,p=1$" + salt + "$" + sum:                       unsupported,
		"$2y$03$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.uy":            cost,
		"$2y$15$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.uy":            cost,
		"$2y$14$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.uy":            cost,
		"$2y$04$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.uy\n":          malformed,
		"$2y$04$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.u":             malformed,
		"$2y$04$G9V5i0s9TXCLX6Bkoip7Hev0PECM.q2cjfA1meSphS44gCbal2.u!":            malformed,
		argon("m=65537,t=1,p=1"):                                                  cost,
		argon("m=8192,t=11,p=1"):                                                  cost,
		argon("m=8192,t=1,p=9"):                                                   cost,
		argon("m=99999999999999999999,t=1,p=1"):                                   cost,
		argon("m=65536,t=5,p=1"):                                                  cost, // m×t over maxArgonWork
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt[:4] + "\n" + salt[4:] + "$" + sum: malformed,
		argon("m=8192,t=0,p=1"):                                                   malformed,
		argon("m=8192,t=1"):                                                       malformed,
		argon("m=8192,t=1,p=1,x=1"):                                               malformed,
		argon("m=8192,t=1,t=1"):                                                   malformed,
		argon("m=-1,t=1,p=1"):                                                     malformed,
		"$argon2id$v=19$m=8192,t=1,p=1$" + base64.RawStdEncoding.EncodeToString([]byte("short")) + "$" + sum:   malformed,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$" + base64.RawStdEncoding.EncodeToString([]byte("tiny")):   malformed,
		"$argon2id$v=19$m=8192,t=1,p=1$" + salt + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 65)): malformed,
		"$argon2id$v=19$m=8192,t=1,p=1$%%%$" + sum:                                                             malformed,
		pbkdf("999"):                              cost,
		pbkdf("2000001"):                          cost,
		pbkdf("18446744073709551616"):             cost,
		pbkdf("x"):                                malformed,
		"$pbkdf2-sha256$i=1000$" + salt:           malformed,
		"pbkdf2_sha256$1000$$" + sum:              malformed,
		"pbkdf2_sha256$1000$short$" + sum:         malformed, // salt under 8 bytes
		"$pbkdf2-sha1$i=1000$" + salt + "$" + sum: malformed, // 32-byte hash, 20-byte digest
		"pbkdf2_sha256$999999999$saltsalt$" + sum: cost,
		"pbkdf2_sha256$1000$saltsalt":             malformed,
		fire("m=16,r=8"):                          cost,
		fire("m=15,r=17"):                         cost,
		fire("m=0,r=8"):                           malformed,
		fire("m=14"):                              malformed,
		"$firebase-scrypt$m=14,r=8$" + salt + "$" + sum + "$Bw==":     malformed,
		"$firebase-scrypt$m=14,r=8$" + salt + "$" + sum + "$Bw==$AA":  malformed, // signer shorter than the hash
		"$firebase-scrypt$m=14,r=8$" + salt + "$" + sum + "$!$" + sum: malformed,
		"$2y$04$" + strings.Repeat("a", MaxHashLength):                malformed,
	} {
		err := Hasher{}.CheckHash(hash)
		var e *errx.Error
		if !errors.As(err, &e) || e.Type != errx.TypeValidation || e.Message != want {
			t.Errorf("CheckHash(%.60q) = %v, want %q", hash, err, want)
		}
	}
	// Refused hashes never match and cost one dummy bcrypt, never the
	// refused work (a few suffice: each compare is a full bcrypt).
	for _, hash := range []string{"plaintext", argon("m=65537,t=1,p=1"), pbkdf("2000001"), fire("m=16,r=8"), "$2y$99$"} {
		if m, s := (Hasher{}).Compare(hash, password); m || s {
			t.Errorf("Compare(%.60q) = %v, %v", hash, m, s)
		}
	}
	// 128·r·N = 64 MiB (m=15, r=16) is the largest cost accepted.
	for _, params := range []string{"m=15,r=16", "m=14,r=16"} {
		if err := (Hasher{}).CheckHash(fire(params)); err != nil {
			t.Fatalf("%s must be accepted: %v", params, err)
		}
	}
}

func TestCompareUnknownAccountIsUniform(t *testing.T) {
	if m, s := (Hasher{}).Compare("", password); m || s {
		t.Fatalf("empty hash: %v, %v", m, s)
	}
	// A cheap imported hash answers no sooner than a bcrypt at the
	// configured cost.
	cheap := "$pbkdf2-sha256$i=1000$" + base64.RawStdEncoding.EncodeToString([]byte("saltsalt")) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	start := time.Now()
	(Hasher{}).Compare(cheap, password)
	if took := time.Since(start); took < floor {
		t.Fatalf("cheap hash answered in %s, floor %s", took, floor)
	}
}

func TestHashIsBcryptAtConfiguredCost(t *testing.T) {
	hash, err := Hasher{}.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := bcrypt.Cost([]byte(hash)); err != nil || c != config.BcryptCost {
		t.Fatalf("cost %d, %v", c, err)
	}
	// What Hash writes is what CheckHash accepts.
	if err := (Hasher{}).CheckHash(hash); err != nil {
		t.Fatal(err)
	}
}

func TestPBKDF2MatchesStdlib(t *testing.T) {
	salt := []byte("some-salt-bytes")
	key, err := pbkdf2.Key(sha256.New, password, salt, 5000, 32)
	if err != nil {
		t.Fatal(err)
	}
	hash := "$pbkdf2-sha256$i=5000$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
	if m, s := (Hasher{}).Compare(hash, password); !m || !s {
		t.Fatalf("%v, %v", m, s)
	}
}

// FuzzCheckHash feeds arbitrary strings to the parser and verifier: neither
// may panic, CheckHash must answer with an errx.Validation, and a hash it
// accepts must stay inside the caps (so Compare stays cheap).
func FuzzCheckHash(f *testing.F) {
	for _, v := range vectors {
		f.Add(v.hash)
	}
	f.Add(firebaseSample)
	f.Add("")
	f.Add("$")
	f.Add("$argon2id$v=19$m=1,t=1,p=1$$")
	f.Add("$pbkdf2-sha256$i=99999999999999999999$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA")
	f.Add("$firebase-scrypt$m=15,r=16$AA$AA$AA$AA")
	f.Add("pbkdf2_sha256$$$")
	f.Add("$2y$99$")
	f.Fuzz(func(t *testing.T, hash string) {
		err := Hasher{}.CheckHash(hash)
		if err != nil {
			var e *errx.Error
			if !errors.As(err, &e) || e.Type != errx.TypeValidation {
				t.Fatalf("not a validation error: %v", err)
			}
			return
		}
		p, perr := parse(hash)
		if perr != nil {
			t.Fatalf("CheckHash accepted what parse refuses: %v", perr)
		}
		switch p.scheme {
		case argon2Scheme:
			if p.memory > maxArgonMemory || p.turns > maxArgonTime || p.threads > maxArgonThreads {
				t.Fatalf("argon2 over cap: %+v", p)
			}
		case pbkdf2Scheme:
			if p.iterations < minPBKDF2Iterations || p.iterations > maxPBKDF2Iterations {
				t.Fatalf("pbkdf2 over cap: %d", p.iterations)
			}
		case firebaseScheme:
			if 128*uint64(p.rounds)*(1<<p.memCost) > maxFirebaseBytes {
				t.Fatalf("firebase over cap: %+v", p)
			}
		}
	})
}

// FuzzCompare runs verification itself on accepted parameters, bounded so a
// fuzz round stays quick: it must never panic and never match garbage.
func FuzzCompare(f *testing.F) {
	for _, v := range vectors {
		if !strings.HasPrefix(v.hash, "$2y$") {
			f.Add(v.hash, password)
		}
	}
	f.Add(firebaseSample, "user1password")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, hash, pw string) {
		p, err := parse(hash)
		if err != nil {
			return // refused hashes only cost a dummy bcrypt (TestCheckHashRefusals)
		}
		// Keep fuzzing fast: skip the expensive accepted parameters.
		if p.scheme == bcryptScheme || p.iterations > 20000 || p.memory > 8192 || p.turns > 2 || p.memCost > 10 {
			return
		}
		m, s := (Hasher{}).Compare(hash, pw)
		if s && !m {
			t.Fatal("stale without a match")
		}
	})
}
