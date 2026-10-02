// Package action helps an endpoint answer IAMKit actions (targets bound to
// conditions such as function:pre_sign_in or function:pre_access_token).
//
// IAMKit posts the condition's Input as JSON, signed per Standard Webhooks
// with the target's whsec_ secret, and waits up to the target's timeout. A
// target of kind "call" answers 204 (no changes) or 200 with a Response:
//
//	func handle(w http.ResponseWriter, r *http.Request) {
//		in, err := action.Verify(secret, r)
//		if err != nil {
//			http.Error(w, "bad signature", http.StatusUnauthorized)
//			return
//		}
//		switch in.Condition {
//		case action.PreSignIn:
//			if blocked(in.User.Email) {
//				action.Write(w, action.Deny("Your account is under review."))
//				return
//			}
//		case action.PreAccessToken:
//			action.Write(w, action.Response{Claims: map[string]any{"tier": tier(in.User.ID)}})
//			return
//		}
//		w.WriteHeader(http.StatusNoContent)
//	}
//
// A non-2xx status, a timeout or an invalid answer (a reserved claim, a
// field the condition cannot patch) is a failure: the flow stops with
// ACTION_FAILED when the target interrupts on error, otherwise it goes on
// without the target's changes.
package action

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/Abraxas-365/iamkit/sdk/webhook"
)

// Conditions.
const (
	PreSignIn       = "function:pre_sign_in"
	PreRegistration = "function:pre_registration"
	PostFederation  = "function:post_federation"
	PreAccessToken  = "function:pre_access_token"
	PreIDToken      = "function:pre_id_token"
	PreUserInfo     = "function:pre_userinfo"
	UserCreate      = "request:user.create"
	UserUpdate      = "request:user.update"
	MembershipAdd   = "request:membership.create"
)

// MaxBody caps the request body read by Verify.
const MaxBody = 1 << 20

// Input is what IAMKit sends; fields not relevant to the condition are
// empty. No secrets or credentials are ever included.
type Input struct {
	Condition      string    `json:"condition"`
	EnvironmentID  string    `json:"environment_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	ApplicationID  string    `json:"application_id,omitempty"`
	ClientID       string    `json:"client_id,omitempty"`
	User           *User     `json:"user,omitempty"`
	AMR            []string  `json:"amr,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	Identity       *Identity `json:"identity,omitempty"`
	// Request is the body of a request:* condition (passwords left out).
	Request json.RawMessage `json:"request,omitempty"`
}

// User is the user the flow is about. ID is empty before registration.
type User struct {
	ID       string `json:"id,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Username string `json:"username,omitempty"`
}

// Identity is the external identity of post_federation and federated
// pre_registration.
type Identity struct {
	ConnectionID string `json:"connection_id"`
	Provider     string `json:"provider"`
	Subject      string `json:"subject"`
	Email        string `json:"email,omitempty"`
	Name         string `json:"name,omitempty"`
}

// Response is a call target's answer. Deny refuses the flow (where the
// condition allows it) with Message, shown to the user (≤ 200 characters).
// Claims are added to the token or UserInfo response (token and UserInfo
// conditions; reserved names such as sub, aud or permissions are refused;
// 4 KiB at most). Patch replaces the fields the condition lists (for
// example name on post_federation and request:user.update).
type Response struct {
	Deny    bool           `json:"deny,omitempty"`
	Message string         `json:"message,omitempty"`
	Claims  map[string]any `json:"claims,omitempty"`
	Patch   map[string]any `json:"patch,omitempty"`
}

// Deny is a Response refusing the flow with message.
func Deny(message string) Response { return Response{Deny: true, Message: message} }

// Verify reads r's body, checks its signature against secret (whsec_…;
// during a rotation either secret verifies) and decodes the input.
func Verify(secret string, r *http.Request) (Input, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody))
	if err != nil {
		return Input{}, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := webhook.VerifyBody(secret, r.Header, body, time.Now()); err != nil {
		return Input{}, err
	}
	var in Input
	if err := json.Unmarshal(body, &in); err != nil {
		return Input{}, err
	}
	return in, nil
}

// Write answers with response (200, JSON).
func Write(w http.ResponseWriter, response Response) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(response)
}
