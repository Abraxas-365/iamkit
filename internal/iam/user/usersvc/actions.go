package usersvc

import (
	"context"
	"encoding/json"

	"github.com/Abraxas-365/iamkit/internal/errx"
	"github.com/Abraxas-365/iamkit/internal/iam/action"
	"github.com/Abraxas-365/iamkit/internal/iam/user"
	"github.com/Abraxas-365/iamkit/internal/identity"
)

// SetActions runs the environment's request:user.* hooks.
func (s *Service) SetActions(actions user.Actions) { s.actions = actions }

// createRequest is what request:user.create sees (never the password).
type createRequest struct {
	Kind             user.Kind               `json:"kind"`
	Email            string                  `json:"email,omitempty"`
	Name             string                  `json:"name"`
	Username         string                  `json:"username,omitempty"`
	AvatarURL        string                  `json:"avatar_url,omitempty"`
	HomeOrganization identity.OrganizationID `json:"home_organization_id,omitzero"`
}

// updateRequest is what request:user.update sees.
type updateRequest struct {
	ID        identity.UserID `json:"id"`
	Name      *string         `json:"name,omitempty"`
	Active    *bool           `json:"active,omitempty"`
	AvatarURL *string         `json:"avatar_url,omitempty"`
	Username  *string         `json:"username,omitempty"`
	Phone     *string         `json:"phone,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// beforeCreate runs request:user.create; a patch is checked like the
// request itself.
func (s *Service) beforeCreate(ctx context.Context, environment identity.EnvironmentID, input user.Create) (user.Create, error) {
	if s.actions == nil {
		return input, nil
	}
	result, err := s.actions.Run(ctx, environment, action.UserCreate, func() action.Input {
		body, _ := json.Marshal(createRequest{Kind: input.Kind, Email: input.Email, Name: input.Name, Username: input.Username, AvatarURL: input.AvatarURL, HomeOrganization: input.HomeOrganization})
		return action.Input{Request: body}
	})
	if err != nil || len(result.Patch) == 0 {
		return input, err
	}
	if v, ok := result.Patch["name"]; ok {
		input.Name = v
	}
	if v, ok := result.Patch["username"]; ok {
		input.Username = v
	}
	if v, ok := result.Patch["avatar_url"]; ok {
		input.AvatarURL = v
	}
	if err = input.Validate(); err != nil {
		return input, patchError(err)
	}
	return input, nil
}

// beforeUpdate runs request:user.update.
func (s *Service) beforeUpdate(ctx context.Context, environment identity.EnvironmentID, id identity.UserID, input user.Update) (user.Update, error) {
	if s.actions == nil {
		return input, nil
	}
	result, err := s.actions.Run(ctx, environment, action.UserUpdate, func() action.Input {
		body, _ := json.Marshal(updateRequest{ID: id, Name: input.Name, Active: input.Active, AvatarURL: input.AvatarURL, Username: input.Username, Phone: input.Phone, Metadata: input.Metadata})
		return action.Input{User: &action.UserInput{ID: &id}, Request: body}
	})
	if err != nil || len(result.Patch) == 0 {
		return input, err
	}
	if v, ok := result.Patch["name"]; ok {
		input.Name = &v
	}
	if v, ok := result.Patch["avatar_url"]; ok {
		input.AvatarURL = &v
	}
	input = input.Normalize()
	if err = input.Validate(); err != nil {
		return input, patchError(err)
	}
	return input, nil
}

// patchError: an action's patch broke the request; the target is at fault,
// so the message says so.
func patchError(err error) error {
	var e *errx.Error
	message := "an action changed the request into an invalid one"
	if errx.As(err, &e) {
		message += ": " + e.Message
	}
	out := errx.Business(message)
	out.Code = "ACTION_FAILED"
	return out
}
