package oauthhttp

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Abraxas-365/iamkit/internal/iam/oauth/adapters/oauthfosite"
	"github.com/ory/fosite"
)

// W5-3: fosite wraps a storage error as server_error (WithWrap, inside a
// stack); a client no longer admitted when its token is stored is an ended
// grant (invalid_grant), any other storage failure stays a server error.
func TestIssueErrorEndsGrantsOfClientsNoLongerAdmitted(t *testing.T) {
	wrapped := fosite.ErrServerError.WithWrap(fmt.Errorf("persist: %w", oauthfosite.ErrNotAdmitted)).WithDebug("x")
	got := issueError(fmt.Errorf("stack: %w", wrapped))
	var rfc *fosite.RFC6749Error
	if !errors.As(got, &rfc) || rfc.ErrorField != fosite.ErrInvalidGrant.ErrorField {
		t.Fatalf("issueError(not admitted) = %v, want invalid_grant", got)
	}
	other := fosite.ErrServerError.WithWrap(errors.New("connection reset"))
	if got := issueError(other); !errors.As(got, &rfc) || rfc.ErrorField != fosite.ErrServerError.ErrorField {
		t.Fatalf("issueError(other) = %v, want server_error", got)
	}
}
