package authpassword

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"math"
	"strconv"
	"strings"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
)

// Caps on what a stored hash may ask a login to compute. They are checked
// when a hash is imported (CheckHash) and again at every verification, so a
// row written some other way cannot make a sign-in expensive.
const (
	MaxHashLength = 1024 // bytes of the whole string

	minBcryptCost = 4
	maxBcryptCost = 13 // about 2× config.BcryptCost

	maxArgonMemory  = 64 * 1024 // KiB
	maxArgonTime    = 10
	maxArgonThreads = 8
	maxArgonWork    = 256 * 1024 // memory (KiB) × passes: m=65536,t=4 or m=19456,t=13

	minPBKDF2Iterations = 1000
	maxPBKDF2Iterations = 2_000_000

	minSalt = 8
	minSum  = 16
	maxSum  = 64

	maxFirebaseMemCost = 15
	maxFirebaseRounds  = 16
	maxFirebaseBytes   = 64 << 20 // 128·r·N
)

// The three reasons CheckHash refuses a hash, one message each.
func errUnsupported() error { return errx.Validation("password_hash format is not supported") }
func errCost() error {
	return errx.Validation("password_hash parameters exceed the allowed cost")
}
func errMalformed() error { return errx.Validation("password_hash is malformed") }

type scheme int

const (
	bcryptScheme scheme = iota + 1
	argon2Scheme
	pbkdf2Scheme
	firebaseScheme
)

// parsed is a hash string taken apart and checked against the caps.
type parsed struct {
	scheme scheme
	stale  bool
	// bcrypt keeps the string itself.
	raw string
	// argon2
	id            bool // argon2id, else argon2i
	memory, turns uint32
	threads       uint8
	// pbkdf2
	digest     func() hash.Hash
	iterations int
	// firebase
	memCost, rounds int
	separator       []byte
	signer          []byte
	// shared
	salt, sum []byte
}

// parse reads hash by its prefix. The error is one of the errx.Validation
// values above.
func parse(hash string) (parsed, error) {
	// base64 decoding skips line breaks; refuse them (and any other
	// whitespace) so what is stored is exactly what was checked.
	if len(hash) > MaxHashLength || strings.ContainsAny(hash, " \t\r\n\v\f") {
		return parsed{}, errMalformed()
	}
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return parseBcrypt(hash)
	case strings.HasPrefix(hash, "$argon2id$"), strings.HasPrefix(hash, "$argon2i$"):
		return parseArgon2(hash)
	case strings.HasPrefix(hash, "$pbkdf2-sha"):
		return parsePBKDF2(hash)
	case strings.HasPrefix(hash, "pbkdf2_sha"):
		return parseDjango(hash)
	case strings.HasPrefix(hash, "$firebase-scrypt$"):
		return parseFirebase(hash)
	}
	return parsed{}, errUnsupported()
}

func parseBcrypt(hash string) (parsed, error) {
	// $2b$12$ + 22 salt + 31 hash characters.
	if len(hash) != 60 || hash[6] != '$' {
		return parsed{}, errMalformed()
	}
	for _, c := range []byte(hash[7:]) {
		if !(c == '.' || c == '/' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
			return parsed{}, errMalformed()
		}
	}
	if hash[4] < '0' || hash[4] > '9' || hash[5] < '0' || hash[5] > '9' {
		return parsed{}, errMalformed()
	}
	cost := int(hash[4]-'0')*10 + int(hash[5]-'0')
	if cost < minBcryptCost || cost > maxBcryptCost {
		return parsed{}, errCost()
	}
	// Any other cost is stale: lower is weak, higher is slow at every sign-in.
	return parsed{scheme: bcryptScheme, raw: hash, stale: cost != config.BcryptCost || hash[2] == 'y'}, nil
}

func parseArgon2(raw string) (parsed, error) {
	parts := strings.Split(raw, "$") // "", variant, v=19, m=,t=,p=, salt, hash
	if len(parts) == 5 && strings.HasPrefix(parts[2], "m=") {
		return parsed{}, errUnsupported() // version 0x10, no v= field
	}
	if len(parts) != 6 {
		return parsed{}, errMalformed()
	}
	if parts[2] != "v=19" {
		if strings.HasPrefix(parts[2], "v=") {
			return parsed{}, errUnsupported()
		}
		return parsed{}, errMalformed()
	}
	params, err := keyValues(parts[3], "m", "t", "p")
	if err != nil {
		return parsed{}, err
	}
	m, t, p := params[0], params[1], params[2]
	if m == 0 || t == 0 || p == 0 || m < 8*p {
		return parsed{}, errMalformed()
	}
	if m > maxArgonMemory || t > maxArgonTime || p > maxArgonThreads || m*t > maxArgonWork {
		return parsed{}, errCost()
	}
	salt, sum, err := saltAndSum(parts[4], parts[5], minSalt, decodeStd)
	if err != nil {
		return parsed{}, err
	}
	return parsed{scheme: argon2Scheme, stale: true, id: parts[1] == "argon2id",
		memory: uint32(m), turns: uint32(t), threads: uint8(p), salt: salt, sum: sum}, nil
}

// parsePBKDF2 reads the PHC form ($pbkdf2-sha256$i=N$salt$hash, standard
// base64) and passlib's ($pbkdf2-sha256$N$salt$hash, "." for "+").
func parsePBKDF2(raw string) (parsed, error) {
	parts := strings.Split(raw, "$") // "", pbkdf2-shaX, iterations, salt, hash
	if len(parts) != 5 {
		return parsed{}, errMalformed()
	}
	digest := digestOf(strings.TrimPrefix(parts[1], "pbkdf2-"))
	if digest == nil {
		return parsed{}, errUnsupported()
	}
	decode, count := decodeAB64, parts[2]
	if rest, ok := strings.CutPrefix(count, "i="); ok {
		decode, count = decodeStd, rest
	}
	n, err := number(count)
	if err != nil {
		return parsed{}, err
	}
	salt, sum, err := saltAndSum(parts[3], parts[4], minSalt, decode)
	if err != nil {
		return parsed{}, err
	}
	return pbkdf2Of(digest, n, salt, sum)
}

// parseDjango reads pbkdf2_sha256$N$salt$base64: the salt is the text itself.
func parseDjango(raw string) (parsed, error) {
	parts := strings.Split(raw, "$")
	if len(parts) != 4 {
		return parsed{}, errMalformed()
	}
	var digest func() hash.Hash
	switch parts[0] {
	case "pbkdf2_sha256":
		digest = sha256.New
	case "pbkdf2_sha1":
		digest = sha1.New
	default:
		return parsed{}, errUnsupported()
	}
	n, err := number(parts[1])
	if err != nil {
		return parsed{}, err
	}
	if len(parts[2]) < minSalt {
		return parsed{}, errMalformed()
	}
	sum, err := decodeStd(parts[3])
	if err != nil || len(sum) < minSum || len(sum) > maxSum {
		return parsed{}, errMalformed()
	}
	return pbkdf2Of(digest, n, []byte(parts[2]), sum)
}

func pbkdf2Of(digest func() hash.Hash, n uint64, salt, sum []byte) (parsed, error) {
	if n < minPBKDF2Iterations || n > maxPBKDF2Iterations {
		return parsed{}, errCost()
	}
	// A hash longer than the digest makes pbkdf2 run every iteration once
	// per extra block; real exports store exactly one digest.
	if len(sum) > digest().Size() {
		return parsed{}, errMalformed()
	}
	return parsed{scheme: pbkdf2Scheme, stale: true, digest: digest, iterations: int(n), salt: salt, sum: sum}, nil
}

func digestOf(name string) func() hash.Hash {
	switch name {
	case "sha1":
		return sha1.New
	case "sha256":
		return sha256.New
	case "sha512":
		return sha512.New
	}
	return nil
}

// parseFirebase reads $firebase-scrypt$m=14,r=8$salt$hash$separator$signer
// (all standard base64).
func parseFirebase(raw string) (parsed, error) {
	parts := strings.Split(raw, "$") // "", firebase-scrypt, params, salt, hash, separator, signer
	if len(parts) != 7 {
		return parsed{}, errMalformed()
	}
	params, err := keyValues(parts[2], "m", "r")
	if err != nil {
		return parsed{}, err
	}
	m, r := params[0], params[1]
	if m == 0 || r == 0 {
		return parsed{}, errMalformed()
	}
	if m > maxFirebaseMemCost || r > maxFirebaseRounds || 128*r*(uint64(1)<<m) > maxFirebaseBytes {
		return parsed{}, errCost()
	}
	salt, sum, err := saltAndSum(parts[3], parts[4], 1, decodeStd)
	if err != nil {
		return parsed{}, err
	}
	separator, err := decodeStd(parts[5])
	if err != nil {
		return parsed{}, errMalformed()
	}
	signer, err := decodeStd(parts[6])
	// The stored hash is the signer key encrypted: as long as the key.
	if err != nil || len(signer) < minSum || len(signer) > maxSum || len(signer) != len(sum) {
		return parsed{}, errMalformed()
	}
	return parsed{scheme: firebaseScheme, stale: true, memCost: int(m), rounds: int(r),
		salt: salt, sum: sum, separator: separator, signer: signer}, nil
}

// keyValues reads "a=1,b=2" holding exactly keys, in any order.
func keyValues(s string, keys ...string) ([]uint64, error) {
	fields := strings.Split(s, ",")
	if len(fields) != len(keys) {
		return nil, errMalformed()
	}
	out := make([]uint64, len(keys))
	seen := make([]bool, len(keys))
	for _, f := range fields {
		key, value, ok := strings.Cut(f, "=")
		if !ok {
			return nil, errMalformed()
		}
		i := indexOf(keys, key)
		if i < 0 || seen[i] {
			return nil, errMalformed()
		}
		n, err := number(value)
		if err != nil {
			return nil, err
		}
		out[i], seen[i] = n, true
	}
	return out, nil
}

func indexOf(keys []string, key string) int {
	for i, k := range keys {
		if k == key {
			return i
		}
	}
	return -1
}

// number reads a decimal parameter; one too large for 64 bits reads as the
// largest value, which every cap refuses.
func number(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	switch {
	case errors.Is(err, strconv.ErrRange):
		return math.MaxUint64, nil
	case err != nil:
		return 0, errMalformed()
	}
	return n, nil
}

// saltAndSum decodes a salt of at least minSalt bytes and a 16–64 byte hash
// (a hash of any non-zero length when minSum was relaxed by the caller).
func saltAndSum(salt, sum string, minSaltBytes int, decode func(string) ([]byte, error)) ([]byte, []byte, error) {
	s, err := decode(salt)
	if err != nil || len(s) < minSaltBytes {
		return nil, nil, errMalformed()
	}
	h, err := decode(sum)
	if err != nil || len(h) < minSum || len(h) > maxSum {
		return nil, nil, errMalformed()
	}
	return s, h, nil
}

// decodeStd decodes standard base64 with or without padding.
func decodeStd(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// decodeAB64 decodes passlib's "adapted base64": "." stands for "+".
func decodeAB64(s string) ([]byte, error) {
	return decodeStd(strings.ReplaceAll(s, ".", "+"))
}
