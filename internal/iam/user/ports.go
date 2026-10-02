package user

import (
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/identity"
	"github.com/Abraxas-365/iamkit/internal/query"
)

type Commands interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create) (identity.UserID, error)
	Update(ctx context.Context, m Mutation, user identity.UserID, input Update) error
	// Deactivate suspends the user (active=false, audited
	// user.deactivated): sessions end and nothing signs in.
	Deactivate(ctx context.Context, m Mutation, user identity.UserID) error
	// Reactivate lifts a suspension (audited user.reactivated).
	Reactivate(ctx context.Context, m Mutation, user identity.UserID) error
	Delete(ctx context.Context, m Mutation, user identity.UserID) error
	// Unlock clears the user's wrong-password count and lockout.
	Unlock(ctx context.Context, m Mutation, user identity.UserID) error
	// SetMetadata sets one metadata key (audited user.metadata_set).
	SetMetadata(ctx context.Context, m Mutation, user identity.UserID, key string, value json.RawMessage) error
	// DeleteMetadata removes one key (audited user.metadata_deleted);
	// NotFound when it is not set.
	DeleteMetadata(ctx context.Context, m Mutation, user identity.UserID, key string) error
	// UpdateProfile merges a patch (top-level keys, null removes) into the
	// profile and checks the result against the schema (audited
	// user.profile_updated).
	UpdateProfile(ctx context.Context, m Mutation, user identity.UserID, patch json.RawMessage) (json.RawMessage, error)
	// UpdateOwnProfile is UpdateProfile limited to x-iamkit-self: write
	// properties; it answers the user's self-visible profile.
	UpdateOwnProfile(ctx context.Context, m Mutation, user identity.UserID, patch json.RawMessage) (map[string]json.RawMessage, error)
	// SaveSchema replaces the environment's profile schema (audited
	// user.schema_updated); existing profiles are counted, not rewritten.
	SaveSchema(ctx context.Context, m Mutation, schema json.RawMessage) (SchemaSaved, error)
	// DeleteSchema removes it: profiles are no longer checked.
	DeleteSchema(ctx context.Context, m Mutation) error
}

// AccessTokenCommands manage machine users' personal access tokens.
type AccessTokenCommands interface {
	// CreateAccessToken issues a token for a machine user that is a member
	// of the organization, for an application resource (audited
	// user.access_token_created); the secret is returned only here.
	CreateAccessToken(ctx context.Context, m Mutation, user identity.UserID, input NewAccessToken) (IssuedAccessToken, error)
	// RevokeAccessToken ends the token and every session exchanged from
	// it (audited user.access_token_revoked).
	RevokeAccessToken(ctx context.Context, m Mutation, user identity.UserID, token identity.AccessTokenID) error
}

// AccessTokenQueries read personal access tokens (never their secrets).
type AccessTokenQueries interface {
	AccessTokens(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, page query.Pagination) (query.Paginated[AccessToken], error)
}

// AccessTokenRepository persists personal access tokens.
type AccessTokenRepository interface {
	// CreateAccessToken stores the token after checking, in the same
	// transaction, that the user is a machine user and a member of the
	// organization and that the application serves the resource; it audits
	// m.Action.
	CreateAccessToken(ctx context.Context, m Mutation, token AccessToken, secretHash []byte) (AccessToken, error)
	RevokeAccessToken(ctx context.Context, m Mutation, user identity.UserID, token identity.AccessTokenID) error
	AccessTokens(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, page query.Pagination) (query.Paginated[AccessToken], error)
}

// KeyCommands manage machine users' keys (RFC 7523 JWT-bearer login).
type KeyCommands interface {
	// AddKey stores an uploaded public key or generates a pair, returning
	// the private half only here (audited user.key_added).
	AddKey(ctx context.Context, m Mutation, user identity.UserID, input NewKey) (IssuedKey, error)
	// RemoveKey deletes the key and ends the sessions opened with it
	// (audited user.key_removed).
	RemoveKey(ctx context.Context, m Mutation, user identity.UserID, key identity.UserKeyID) error
}

// KeyQueries read machine users' public keys.
type KeyQueries interface {
	Keys(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, page query.Pagination) (query.Paginated[Key], error)
}

// KeyRepository persists machine users' keys.
type KeyRepository interface {
	// AddKey stores the key after checking, in the same transaction, that
	// the user is a machine user holding fewer than MaxKeys; it audits
	// m.Action.
	AddKey(ctx context.Context, m Mutation, key Key) (Key, error)
	RemoveKey(ctx context.Context, m Mutation, user identity.UserID, key identity.UserKeyID) error
	Keys(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, page query.Pagination) (query.Paginated[Key], error)
}

// KeyPairs generates key pairs for machine users who do not bring their
// own public key.
type KeyPairs interface {
	// Generate returns the public JSON Web Key and the PEM (PKCS #8)
	// private key.
	Generate() (public json.RawMessage, private string, err error)
}

// Secrets generates personal access token secrets and their hashes.
type Secrets interface {
	Generate(prefix string) (raw string, hash []byte, err error)
}

// PhoneCommands let users verify their own phone number (self-service
// /identity/v1/me/phone). The number is not a sign-in identifier.
type PhoneCommands interface {
	// StartPhoneVerification texts a code (purpose phone_verification) to
	// phone; the user's number changes only once the code is entered.
	StartPhoneVerification(ctx context.Context, m Mutation, user identity.UserID, phone string) (PhoneCodeSent, error)
	// VerifyPhone makes the pending number the user's verified phone
	// (audited user.phone_verified); a wrong code answers INVALID_CODE and
	// counts, config.MFAAttempts wrong codes discard it.
	VerifyPhone(ctx context.Context, m Mutation, user identity.UserID, code string) error
	// RemovePhone clears the number (audited user.phone_removed). An
	// enrolled SMS second factor keeps its own number.
	RemovePhone(ctx context.Context, m Mutation, user identity.UserID) error
}

// PhoneRepository persists pending phone verifications.
type PhoneRepository interface {
	// EditPhoneVerification runs edit on the user's pending verification
	// (zero when none) under a lock on a human user and stores its result;
	// an error from edit stores nothing.
	EditPhoneVerification(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, edit func(current PhoneVerification) (PhoneVerification, error)) error
	// ConfirmPhone consumes a live verification whose code hash matches and
	// sets it as the verified phone with an audit of m.Action; false when
	// none matches.
	ConfirmPhone(ctx context.Context, m Mutation, user identity.UserID, codeHash []byte) (bool, error)
	// FailPhoneCode counts a wrong code and discards it at limit.
	FailPhoneCode(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, limit int) error
	// RemovePhone clears the number and any pending verification with an
	// audit of m.Action.
	RemovePhone(ctx context.Context, m Mutation, user identity.UserID) error
}

// SMS texts a code through the environment's SMS provider (implemented by
// the authentication module).
type SMS interface {
	SendSMS(ctx context.Context, environment identity.EnvironmentID, phone, purpose, code string) error
}

// CodeHasher hashes verification codes.
type CodeHasher interface {
	Hash(raw string) []byte
}
type Queries interface {
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, page query.Pagination) (query.Paginated[User], error)
	Find(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (User, error)
	// Metadata returns one metadata value; NotFound when unset.
	Metadata(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, key string) (json.RawMessage, error)
	// Schema returns the environment's profile schema (Version 0: none).
	Schema(ctx context.Context, environment identity.EnvironmentID) (Schema, error)
	// OwnProfile returns the x-iamkit-self properties of the user's profile.
	OwnProfile(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (map[string]json.RawMessage, error)
	// Claims returns the claims of the user keyed by claim name: for the
	// profile scope picture (the avatar), preferred_username (when set) and
	// the x-iamkit-claim properties of the profile; for the phone scope
	// phone_number and phone_number_verified (when a number is set).
	Claims(ctx context.Context, environment identity.EnvironmentID, user identity.UserID, scopes []string) (map[string]json.RawMessage, error)
}

type Repository interface {
	Create(ctx context.Context, environment identity.EnvironmentID, input Create, passwordHash string) (identity.UserID, error)
	List(ctx context.Context, environment identity.EnvironmentID, filter Filter, page query.Pagination) (query.Paginated[User], error)
	Find(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (User, error)
	Update(ctx context.Context, m Mutation, user identity.UserID, input Update) error
	// SetActive sets active and audits m.Action in one transaction.
	SetActive(ctx context.Context, m Mutation, user identity.UserID, active bool) error
	Delete(ctx context.Context, m Mutation, user identity.UserID) error
	Unlock(ctx context.Context, m Mutation, user identity.UserID) error
	// EditMetadata runs edit on the user's metadata under a row lock and
	// stores its result with an audit of m.Action; edit may return an
	// error to abort.
	EditMetadata(ctx context.Context, m Mutation, user identity.UserID, edit func(current json.RawMessage) (json.RawMessage, error)) error
	// EditProfile is EditMetadata for the profile; edit also receives the
	// environment's schema (Version 0: none).
	EditProfile(ctx context.Context, m Mutation, user identity.UserID, edit func(current json.RawMessage, schema Schema) (json.RawMessage, error)) (json.RawMessage, error)
	Profile(ctx context.Context, environment identity.EnvironmentID, user identity.UserID) (json.RawMessage, error)
	Schema(ctx context.Context, environment identity.EnvironmentID) (Schema, error)
	// SaveSchema stores the schema, bumps its version and audits.
	SaveSchema(ctx context.Context, m Mutation, schema json.RawMessage) (Schema, error)
	DeleteSchema(ctx context.Context, m Mutation) error
	// Profiles returns every profile of the environment that is not {}.
	Profiles(ctx context.Context, environment identity.EnvironmentID) ([]ProfileRow, error)
}

// SchemaValidator checks profile schemas and profiles (adapter
// userschema, JSON Schema 2020-12).
type SchemaValidator interface {
	// Check compiles a schema; remote references are refused.
	Check(schema json.RawMessage) error
	// Validate checks a profile against a schema.
	Validate(schema, profile json.RawMessage) error
}
type PasswordHasher interface {
	Hash(password string) (string, error)
}

// PasswordPolicy checks a new password against the environment's policy
// (implemented by the authentication module).
type PasswordPolicy interface {
	CheckPassword(ctx context.Context, environment identity.EnvironmentID, password string) error
}

// Actions runs the environment's request hooks (action.Runner):
// request:user.create and request:user.update.
type Actions interface {
	Run(ctx context.Context, environment identity.EnvironmentID, condition string, build func() action.Input) (action.Result, error)
}

// Quota admits a creation within the environment's limits (usage.Commands):
// limit usage.LimitUsers → 422 QUOTA_EXCEEDED.
type Quota interface {
	Admit(ctx context.Context, environment identity.EnvironmentID, limit string) error
}
