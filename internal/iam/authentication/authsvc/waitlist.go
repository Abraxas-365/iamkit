package authsvc

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/i18n"
	"github.com/Abraxas-365/iamkit/internal/iam/authentication"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

// Waitlists implements the operator's side of the sign-up waitlist:
// listing, approving (which emails the sign-up token), rejecting and
// deleting entries. People join through Service.Signup.
type Waitlists struct {
	repository authentication.WaitlistRepository
	secrets    authentication.Secrets
	service    *Service
	now        func() time.Time
}

// NewWaitlists builds the waitlist use cases; service sends the emails
// (after the response, like sign-up codes) and reads the sign-in policy.
func NewWaitlists(repository authentication.WaitlistRepository, secrets authentication.Secrets, service *Service) *Waitlists {
	return &Waitlists{repository: repository, secrets: secrets, service: service, now: time.Now}
}

var (
	_ authentication.WaitlistCommands = (*Waitlists)(nil)
	_ authentication.WaitlistQueries  = (*Waitlists)(nil)
)

func waitlistTarget(id identity.WaitlistEntryID) string { return "/waitlist/" + id.String() }

func (w *Waitlists) List(ctx context.Context, environment identity.EnvironmentID, filter authentication.WaitlistFilter, page query.Pagination) (query.Paginated[authentication.WaitlistEntry], error) {
	if environment.IsZero() {
		return query.Paginated[authentication.WaitlistEntry]{}, errx.NotFound("environment not found")
	}
	if err := filter.Validate(); err != nil {
		return query.Paginated[authentication.WaitlistEntry]{}, err
	}
	return w.repository.ListWaitlist(ctx, environment, filter, page.Normalize())
}

func (w *Waitlists) Find(ctx context.Context, environment identity.EnvironmentID, id identity.WaitlistEntryID) (authentication.WaitlistEntry, error) {
	if environment.IsZero() || id.IsZero() {
		return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
	}
	return w.repository.FindWaitlist(ctx, environment, id)
}

// Approve issues a fresh token for the entry and emails it. The email goes
// out after the decision is stored; when it fails the operator approves
// again, which issues another token.
func (w *Waitlists) Approve(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID) (authentication.WaitlistEntry, error) {
	if m.Environment.IsZero() || id.IsZero() {
		return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
	}
	policy, err := w.service.signInPolicy(ctx, m.Environment)
	if err != nil {
		return authentication.WaitlistEntry{}, err
	}
	return w.approve(ctx, m, id, policy)
}

func (w *Waitlists) approve(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID, policy authentication.SignInPolicy) (authentication.WaitlistEntry, error) {
	raw, hash, err := w.secrets.Generate(authentication.WaitlistTokenPrefix)
	if err != nil {
		return authentication.WaitlistEntry{}, err
	}
	expires := w.now().Add(config.WaitlistApprovalTTL)
	m.Action, m.Target = authentication.ActionWaitlistApprove, waitlistTarget(id)
	entry, err := w.repository.ApproveWaitlist(ctx, m, authentication.WaitlistApproval{ID: id, TokenHash: hash, ExpiresAt: expires})
	if err != nil {
		return authentication.WaitlistEntry{}, err
	}
	message := authentication.Message{Email: entry.Email, Purpose: authentication.PurposeWaitlistApproved, Token: raw,
		Link: authentication.WaitlistLink(policy.WaitlistURL(), raw), ExpiresAt: &expires, Locale: i18n.Match(entry.Locale)}
	w.service.deliverLater(ctx, m.Environment, message, "waitlist_entry", id, "environment", m.Environment, "purpose", message.Purpose)
	return entry, nil
}

// ApproveMany approves the listed entries, or the oldest pending ones, up to
// config.WaitlistMaxApprove. Entries that cannot be approved (decided
// meanwhile, deleted) are skipped, not errors.
func (w *Waitlists) ApproveMany(ctx context.Context, m authentication.Mutation, input authentication.WaitlistApprove) (authentication.WaitlistBulkResult, error) {
	if m.Environment.IsZero() {
		return authentication.WaitlistBulkResult{}, errx.NotFound("environment not found")
	}
	if err := input.Validate(); err != nil {
		return authentication.WaitlistBulkResult{}, err
	}
	policy, err := w.service.signInPolicy(ctx, m.Environment)
	if err != nil {
		return authentication.WaitlistBulkResult{}, err
	}
	ids := input.IDs
	if len(ids) > 1 {
		ids = slices.Clone(ids)
		slices.SortFunc(ids, func(a, b identity.WaitlistEntryID) int { return strings.Compare(a.String(), b.String()) })
		ids = slices.Compact(ids)
	}
	var out authentication.WaitlistBulkResult
	if input.AllPending {
		entries, err := w.repository.PendingWaitlist(ctx, m.Environment, config.WaitlistMaxApprove+1)
		if err != nil {
			return authentication.WaitlistBulkResult{}, err
		}
		if len(entries) > config.WaitlistMaxApprove {
			entries, out.More = entries[:config.WaitlistMaxApprove], true
		}
		for _, e := range entries {
			ids = append(ids, e.ID)
		}
	}
	for _, id := range ids {
		if _, err := w.approve(ctx, m, id, policy); err != nil {
			var e *errx.Error
			if !errx.As(err, &e) || (e.Type != errx.TypeNotFound && e.Code != authentication.CodeWaitlistNotPending) {
				slog.ErrorContext(ctx, "waitlist approval failed", "waitlist_entry", id, "err", err)
			}
			out.Skipped++
			continue
		}
		out.Approved++
	}
	return out, nil
}

// Reject refuses the entry. It is silent unless input.Notify.
func (w *Waitlists) Reject(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID, input authentication.WaitlistRejection) (authentication.WaitlistEntry, error) {
	if m.Environment.IsZero() || id.IsZero() {
		return authentication.WaitlistEntry{}, errx.NotFound("waitlist entry not found")
	}
	if err := input.Validate(); err != nil {
		return authentication.WaitlistEntry{}, err
	}
	m.Action, m.Target = authentication.ActionWaitlistReject, waitlistTarget(id)
	entry, err := w.repository.RejectWaitlist(ctx, m, id)
	if err != nil {
		return authentication.WaitlistEntry{}, err
	}
	if input.Notify {
		message := authentication.Message{Email: entry.Email, Purpose: authentication.PurposeWaitlistRejected, Locale: i18n.Match(entry.Locale)}
		w.service.deliverLater(ctx, m.Environment, message, "waitlist_entry", id, "environment", m.Environment, "purpose", message.Purpose)
	}
	return entry, nil
}

// Delete removes the entry, so the address may join the waitlist again.
func (w *Waitlists) Delete(ctx context.Context, m authentication.Mutation, id identity.WaitlistEntryID) error {
	if m.Environment.IsZero() || id.IsZero() {
		return errx.NotFound("waitlist entry not found")
	}
	m.Action, m.Target = authentication.ActionWaitlistDelete, waitlistTarget(id)
	return w.repository.DeleteWaitlist(ctx, m, id)
}

// joinWaitlist answers a sign-up the waitlist holds back. A new address
// gets an entry and a waitlist_joined email; an address with an entry, an
// account or past the pending cap gets the very same answer and nothing
// else, so the response never tells them apart.
func (s *Service) joinWaitlist(ctx context.Context, tx authentication.SignupTransaction, input authentication.Signup, email string) (authentication.SignupResult, error) {
	answer := authentication.SignupResult{Challenge: identity.NewChallengeID(), Status: authentication.SignupWaitlisted}
	exists, err := tx.AccountExists(ctx, input.Environment, email)
	if err != nil || exists {
		return answer, err
	}
	created, err := tx.JoinWaitlist(ctx, authentication.WaitlistJoin{ID: identity.NewWaitlistEntryID(), Environment: input.Environment,
		Email: email, Name: input.Name, Locale: i18n.Match(input.Locale)})
	if err != nil || !created {
		return answer, err
	}
	if err = tx.Commit(); err != nil {
		return authentication.SignupResult{}, err
	}
	message := authentication.Message{Email: email, Purpose: authentication.PurposeWaitlistJoined, Locale: i18n.Match(input.Locale)}
	s.deliverLater(ctx, input.Environment, message, "environment", input.Environment, "purpose", message.Purpose)
	return answer, nil
}

// waitlistToken resolves a presented approval token; the zero value (no
// error) when there is none or it is not valid.
func (s *Service) waitlistToken(ctx context.Context, tx authentication.SignupTransaction, environment identity.EnvironmentID, token string) (authentication.WaitlistToken, error) {
	if !authentication.WaitlistTokenShape(token) {
		return authentication.WaitlistToken{}, nil
	}
	found, err := tx.WaitlistToken(ctx, environment, s.secrets.Hash(token))
	if err != nil {
		var e *errx.Error
		if errx.As(err, &e) && e.Code == authentication.CodeWaitlistToken {
			return authentication.WaitlistToken{}, nil
		}
		return authentication.WaitlistToken{}, err
	}
	return found, nil
}

// WaitlistEmail is the address an approval token was issued to, for the
// hosted sign-up page; every refusal is the same error.
func (s *Service) WaitlistEmail(ctx context.Context, environment identity.EnvironmentID, token string) (string, error) {
	if s.signups == nil || environment.IsZero() || !authentication.WaitlistTokenShape(token) {
		return "", authentication.ErrWaitlistToken()
	}
	tx, err := s.signups.BeginSignup(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	found, err := tx.WaitlistToken(ctx, environment, s.secrets.Hash(token))
	if err != nil {
		return "", err
	}
	return found.Email, nil
}
