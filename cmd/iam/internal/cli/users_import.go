package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

// Limits of POST …/users/import: 100 rows and a 64 KiB body; the CLI stays
// under both (the body is capped at 60 KiB).
const (
	importBatchRows  = 100
	importBatchBytes = 60 * 1024
	importMaxTries   = 5
	importMaxWait    = 2 * time.Minute
	// importRequestTimeout covers one batch: 100 rows, each a transaction
	// and possibly a request:user.create action call.
	importRequestTimeout = 5 * time.Minute
)

// Codes the CLI itself assigns to rows (the server's codes are passed through).
const (
	codeSkipped    = "SKIPPED"
	codeInvalid    = "INVALID"
	codeNotSent    = "NOT_SENT"
	codeNoResult   = "NO_RESULT"
	codeRequestErr = "REQUEST_FAILED"
)

// importUser is the user.Create shape accepted by the import route.
type importUser struct {
	Email         string          `json:"email"`
	Name          string          `json:"name"`
	Username      string          `json:"username,omitempty"`
	ExternalID    string          `json:"external_id,omitempty"`
	PasswordHash  string          `json:"password_hash,omitempty"`
	EmailVerified bool            `json:"email_verified,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	HomeOrg       string          `json:"home_organization_id,omitempty"`
	OTPEnabled    bool            `json:"otp_enabled,omitempty"`
	AvatarURL     string          `json:"avatar_url,omitempty"`
}

// importItem is one input row. Row is its position in the input (see
// usersImportCmd). A non-empty Code marks a row that is not sent: codeSkipped
// for rows left out on purpose, codeInvalid for rows that failed validation.
type importItem struct {
	Row     int
	User    importUser
	Code    string
	Message string
}

func skipped(row int, u importUser, format string, a ...any) importItem {
	return importItem{Row: row, User: u, Code: codeSkipped, Message: fmt.Sprintf(format, a...)}
}

func invalid(row int, u importUser, format string, a ...any) importItem {
	return importItem{Row: row, User: u, Code: codeInvalid, Message: fmt.Sprintf(format, a...)}
}

// importIssue is a line of the --errors file.
type importIssue struct {
	Row        int    `json:"row"`
	ExternalID string `json:"external_id"`
	Email      string `json:"email"`
	Code       string `json:"code"`
	Message    string `json:"message"`
}

type importSummary struct {
	Created, Skipped, Failed int
}

type importOptions struct {
	From                    string
	HomeOrg                 string
	DryRun                  bool
	SkipExisting            bool
	Metadata                bool
	PasswordlessUnsupported bool
	ErrorsFile              string

	// Firebase scrypt parameters (Firebase console › Password hash parameters).
	HashKey       string
	SaltSeparator string
	Rounds        string
	MemCost       string

	Sleep func(time.Duration) // injectable for tests; time.Sleep by default
	Out   io.Writer
	Err   io.Writer
}

func usersImportCmd() *cobra.Command {
	var o importOptions
	cmd := &cobra.Command{
		Use:   "import FILE",
		Short: "Import users, with their password hashes, from another system",
		Long: `Import users from a file (- reads stdin) in batches through
POST …/users/import. Passwords are never asked for: hashes in a supported
format are stored as they are and verified at sign-in (bcrypt, argon2i/id,
pbkdf2, Firebase scrypt); IAMKit replaces them with its own bcrypt at the
user's next successful password sign-in.

Sources (--from):
  iamkit    JSON array or JSON Lines of the user create shape (default):
            email, name, username, external_id, password_hash, email_verified,
            metadata, home_organization_id, otp_enabled, avatar_url
  auth0     Auth0 bulk export, JSON Lines. passwordHash (bcrypt) and
            custom_password_hash are used when already in a supported format.
            --metadata keeps user_metadata/app_metadata under the metadata keys
            auth0_user_metadata/auth0_app_metadata
  firebase  firebase auth:export users.json --format=json. Needs --hash-key,
            --salt-separator, --rounds and --mem-cost (Firebase console ›
            Authentication › Users › Password hash parameters) when any user has
            a password
  clerk     Clerk CSV export (password_digest and password_hasher columns:
            bcrypt, argon2i, argon2id, pbkdf2_sha256 (Django format))
  cognito   aws cognito-idp list-users JSON; Cognito exports no hashes, so users
            are imported without a password

Users without an email, and (unless --passwordless-unsupported) users whose hash
format is not supported, are skipped with a reason. Rows are independent: a
failing row never stops the others. A row is identified by its position in the
input: the line number for JSON Lines, the array index (1-based) for JSON arrays
and the Firebase/Cognito lists, the line number for CSV (the header is line 1).

Requests hold at most 100 users and 60 KiB; 429 and 503 answers are retried
(Retry-After, else 1 s, 2 s, 4 s, 8 s). The command exits non-zero when any row
failed. Password hashes are never printed or written to the --errors file.`,
		Example: `  iam users import users.jsonl
  iam users import export.jsonl --from auth0 --skip-existing --errors failed.jsonl
  IAMKIT_FIREBASE_HASH_KEY=BASE64 iam users import users.json --from firebase --salt-separator BASE64 --rounds 8 --mem-cost 14
  iam users import clerk.csv --from clerk --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			var err error
			if args[0] == "-" {
				data, err = io.ReadAll(cmd.InOrStdin())
			} else {
				data, err = os.ReadFile(args[0])
			}
			if err != nil {
				return err
			}
			if o.HashKey == "" {
				// Kept out of argv (ps, shell history).
				o.HashKey = os.Getenv("IAMKIT_FIREBASE_HASH_KEY")
			}
			o.Out, o.Err = cmd.OutOrStdout(), cmd.ErrOrStderr()
			var c *client
			var path string
			if !o.DryRun {
				c = mustClient(cmd)
				// A batch never takes minutes; a stalled server must not
				// hang the import (the batch is reported as not confirmed).
				c.http = &http.Client{Timeout: importRequestTimeout}
				path = envPath()
			}
			_, err = runImport(c, path, data, o)
			return err
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.From, "from", "iamkit", "Source format: iamkit, auth0, firebase, clerk, cognito")
	f.StringVar(&o.HomeOrg, "home-organization", "", "Home organization ID applied to every user")
	f.BoolVar(&o.DryRun, "dry-run", false, "Convert and validate locally; make no API calls")
	f.BoolVar(&o.SkipExisting, "skip-existing", false, "Count users that already exist (CONFLICT) as skipped instead of failed")
	f.StringVar(&o.ErrorsFile, "errors", "", "Write failed and skipped rows to this JSON Lines file")
	f.BoolVar(&o.Metadata, "metadata", false, "auth0: keep user_metadata and app_metadata as user metadata")
	f.BoolVar(&o.PasswordlessUnsupported, "passwordless-unsupported", false, "Import users whose hash format is not supported without a password instead of skipping them")
	f.StringVar(&o.HashKey, "hash-key", "", "firebase: base64 signer key of the project (prefer the IAMKIT_FIREBASE_HASH_KEY environment variable)")
	f.StringVar(&o.SaltSeparator, "salt-separator", "", "firebase: base64 salt separator of the project")
	f.StringVar(&o.Rounds, "rounds", "", "firebase: scrypt rounds of the project")
	f.StringVar(&o.MemCost, "mem-cost", "", "firebase: scrypt memory cost of the project")
	return cmd
}

// runImport converts data, validates it and, unless dry-run, sends it in
// batches. It returns an error when the input cannot be processed or any row
// failed; the summary is printed in both cases.
func runImport(c *client, path string, data []byte, o importOptions) (importSummary, error) {
	var sum importSummary
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Err == nil {
		o.Err = io.Discard
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.HomeOrg != "" {
		if _, err := uuid.Parse(o.HomeOrg); err != nil {
			return sum, fmt.Errorf("--home-organization is not a UUID")
		}
	}
	var errFile *os.File
	if o.ErrorsFile != "" {
		f, err := os.OpenFile(o.ErrorsFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return sum, fmt.Errorf("opening --errors file: %w", err)
		}
		defer f.Close()
		errFile = f
	}

	items, err := convertImport(data, o)
	if err != nil {
		return sum, err
	}

	var issues []importIssue
	note := func(it importItem, code, msg string) {
		issues = append(issues, importIssue{
			Row: it.Row, ExternalID: it.User.ExternalID, Email: it.User.Email,
			Code: code, Message: redact(msg, it.User.PasswordHash),
		})
	}

	var ready []importItem
	for i := range items {
		it := items[i]
		if it.Code == "" {
			if o.HomeOrg != "" {
				it.User.HomeOrg = o.HomeOrg
			}
			if msg := validateImportUser(it.User); msg != "" {
				it.Code, it.Message = codeInvalid, msg
			}
		}
		switch it.Code {
		case "":
			ready = append(ready, it)
		case codeSkipped:
			sum.Skipped++
			note(it, it.Code, it.Message)
		default:
			sum.Failed++
			note(it, it.Code, it.Message)
		}
	}

	if o.DryRun {
		sum.Created = len(ready)
	} else if len(ready) > 0 {
		r := &importRunner{c: c, path: path + "/users/import", o: o}
		created, skipped, failed := r.send(ready)
		sum.Created += created
		sum.Skipped += skipped.len()
		sum.Failed += failed.len()
		for _, s := range skipped {
			note(s.item, s.code, s.msg)
		}
		for _, s := range failed {
			note(s.item, s.code, s.msg)
		}
	}

	sort.SliceStable(issues, func(i, j int) bool { return issues[i].Row < issues[j].Row })
	if errFile != nil {
		enc := json.NewEncoder(errFile)
		for _, is := range issues {
			if err := enc.Encode(is); err != nil {
				return sum, fmt.Errorf("writing --errors file: %w", err)
			}
		}
	}

	if o.DryRun {
		fmt.Fprintf(o.Out, "dry run: would create %d, skipped %d, failed %d\n", sum.Created, sum.Skipped, sum.Failed)
	} else {
		fmt.Fprintf(o.Out, "created %d, skipped %d, failed %d\n", sum.Created, sum.Skipped, sum.Failed)
	}
	shown := 0
	for _, is := range issues {
		if is.Code == codeSkipped || (o.SkipExisting && is.Code == "CONFLICT") {
			continue
		}
		if shown == 10 {
			fmt.Fprintln(o.Err, "  …")
			break
		}
		fmt.Fprintf(o.Err, "  row %d: %s: %s\n", is.Row, is.Code, is.Message)
		shown++
	}
	if sum.Failed > 0 {
		return sum, fmt.Errorf("%d rows failed", sum.Failed)
	}
	return sum, nil
}

// redact keeps a password hash out of any message.
func redact(msg, hash string) string {
	if hash != "" {
		msg = strings.ReplaceAll(msg, hash, "[redacted]")
	}
	return msg
}

// hashPrefixes are the formats the server accepts (see the plan's hash table);
// the server still checks parameters.
var hashPrefixes = []string{
	"$2a$", "$2b$", "$2y$",
	"$argon2id$", "$argon2i$",
	"$pbkdf2-sha1$", "$pbkdf2-sha256$", "$pbkdf2-sha512$",
	"pbkdf2_sha256$", "pbkdf2_sha1$",
	"$firebase-scrypt$",
}

func hashRecognised(h string) bool {
	for _, p := range hashPrefixes {
		if strings.HasPrefix(h, p) {
			return true
		}
	}
	return false
}

// validateImportUser checks what the CLI can check without the server. The
// message never contains the hash.
func validateImportUser(u importUser) string {
	switch {
	case strings.TrimSpace(u.Email) == "":
		return "email is required"
	case !strings.Contains(u.Email, "@"):
		return "email is not valid"
	case strings.TrimSpace(u.Name) == "":
		return "name is required"
	case u.PasswordHash != "" && !hashRecognised(u.PasswordHash):
		return "password_hash format is not recognised"
	case len(u.PasswordHash) > 1024:
		return "password_hash is too long"
	}
	return ""
}

type importOutcome struct {
	item importItem
	code string
	msg  string
}

type outcomes []importOutcome

func (o outcomes) len() int { return len(o) }

type importRunner struct {
	c    *client
	path string
	o    importOptions
}

// batch is one request: its rows and their marshalled users.
type batch struct {
	items  []importItem
	bodies [][]byte
}

// splitBatches groups rows into requests of at most maxRows users and maxBytes
// of JSON. A row that alone exceeds maxBytes is returned in tooBig.
func splitBatches(items []importItem, maxRows, maxBytes int) (batches []batch, tooBig []importItem) {
	const overhead = len(`{"users":[]}`)
	var cur batch
	size := overhead
	flush := func() {
		if len(cur.items) > 0 {
			batches = append(batches, cur)
		}
		cur, size = batch{}, overhead
	}
	for _, it := range items {
		body, err := json.Marshal(it.User)
		if err != nil || overhead+len(body) > maxBytes {
			tooBig = append(tooBig, it)
			continue
		}
		add := len(body)
		if len(cur.items) > 0 {
			add++ // comma
		}
		if len(cur.items) >= maxRows || size+add > maxBytes {
			flush()
			add = len(body)
		}
		cur.items = append(cur.items, it)
		cur.bodies = append(cur.bodies, body)
		size += add
	}
	flush()
	return batches, tooBig
}

func (b batch) payload() []byte {
	return []byte(`{"users":[` + string(bytes.Join(b.bodies, []byte(","))) + `]}`)
}

type importResponse struct {
	Results []struct {
		Index int    `json:"index"`
		ID    string `json:"id"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	} `json:"results"`
}

// send posts every batch. It returns the created count, the rows skipped
// (existing, with --skip-existing) and the rows that failed.
func (r *importRunner) send(items []importItem) (created int, skippedRows, failedRows outcomes) {
	batches, tooBig := splitBatches(items, importBatchRows, importBatchBytes)
	for _, it := range tooBig {
		failedRows = append(failedRows, importOutcome{it, codeInvalid, "row is too large for one request"})
	}
	var abort string
	for _, b := range batches {
		if abort != "" {
			for _, it := range b.items {
				failedRows = append(failedRows, importOutcome{it, codeNotSent, "not sent: " + abort})
			}
			continue
		}
		resp, serr := r.post(b.payload())
		if serr != nil {
			for _, it := range b.items {
				failedRows = append(failedRows, importOutcome{it, serr.code, serr.message})
			}
			if serr.fatal {
				abort = serr.message
			}
			continue
		}
		seen := make([]bool, len(b.items))
		for _, res := range resp.Results {
			if res.Index < 0 || res.Index >= len(b.items) || seen[res.Index] {
				continue
			}
			seen[res.Index] = true
			it := b.items[res.Index]
			switch {
			case res.Error == nil:
				created++
			case res.Error.Code == "CONFLICT" && r.o.SkipExisting:
				skippedRows = append(skippedRows, importOutcome{it, res.Error.Code, res.Error.Message})
			default:
				failedRows = append(failedRows, importOutcome{it, res.Error.Code, res.Error.Message})
			}
		}
		for i, ok := range seen {
			if !ok {
				failedRows = append(failedRows, importOutcome{b.items[i], codeNoResult, "the server returned no result for this row"})
			}
		}
	}
	return created, skippedRows, failedRows
}

type sendError struct {
	code, message string
	fatal         bool // later batches would fail the same way
}

// post sends one request, retrying 429 and 503.
func (r *importRunner) post(payload []byte) (importResponse, *sendError) {
	var resp importResponse
	for attempt := 1; ; attempt++ {
		status, header, raw, err := r.c.postRaw(r.path, payload)
		if err != nil {
			return resp, &sendError{codeRequestErr, err.Error(), true}
		}
		if status == http.StatusOK {
			if err := json.Unmarshal(raw, &resp); err != nil {
				return resp, &sendError{codeRequestErr, "unreadable response from the server", true}
			}
			return resp, nil
		}
		retryable := status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
		if retryable && attempt < importMaxTries {
			r.o.Sleep(retryDelay(header.Get("Retry-After"), attempt))
			continue
		}
		code, msg := apiErrorOf(status, raw)
		fatal := retryable || status == http.StatusUnauthorized || status == http.StatusForbidden
		return resp, &sendError{code, msg, fatal}
	}
}

// retryDelay honours Retry-After (seconds or an HTTP date), else backs off
// 1 s, 2 s, 4 s, 8 s.
func retryDelay(retryAfter string, attempt int) time.Duration {
	retryAfter = strings.TrimSpace(retryAfter)
	d, ok := time.Duration(-1), false
	if n, err := strconv.Atoi(retryAfter); err == nil && n >= 0 {
		d, ok = time.Duration(n)*time.Second, true
	} else if at, err := http.ParseTime(retryAfter); err == nil {
		d, ok = max(time.Until(at), 0), true
	}
	if !ok {
		return time.Second << (attempt - 1)
	}
	return min(d, importMaxWait)
}

func apiErrorOf(status int, raw []byte) (code, message string) {
	var w struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &w) == nil && w.Error.Message != "" {
		code = w.Error.Code
		if code == "" {
			code = "HTTP_" + strconv.Itoa(status)
		}
		return code, w.Error.Message
	}
	return "HTTP_" + strconv.Itoa(status), fmt.Sprintf("HTTP %d", status)
}

// postRaw POSTs a JSON body and returns the status, headers and body without
// interpreting them.
func (c *client) postRaw(path string, body []byte) (int, http.Header, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("reading response: %w", err)
	}
	return resp.StatusCode, resp.Header, raw, nil
}
