package event

import (
	"net/url"
	"regexp"
	"strings"
)

// Classified is the semantic event an audit entry (action + target)
// describes.
type Classified struct {
	Type    string
	Subject Subject
	// Data holds the ids the target names (organization_id, user_id, …)
	// and its query parameters (domain, method, …).
	Data map[string]any
}

type route struct {
	method, pattern, typ, kind, param string
}

// routes maps write routes whose audit entries still carry the HTTP
// method and path. Patterns are relative to the environment
// (/management/v1/environments/:environment, /api/v1/environments/:environment);
// the /organizations/:organization/admin routes match without /admin.
// param names the path parameter that is the subject id (empty: the
// writer passes it, e.g. for creates). An empty typ means "no event of its
// own" (session ends are written by triggers as session.revoked).
var routes = []route{
	{"PATCH", "/users/:user", UserUpdated, "user", "user"},
	{"DELETE", "/users/:user/permanent", UserDeleted, "user", "user"},
	{"PATCH", "/organizations/:organization", OrganizationUpdated, "organization", "organization"},
	{"PATCH", "/organizations/:organization/members/:user", MembershipUpdated, "user", "user"},
	{"PUT", "/organizations/:organization/members/:user/profile", MembershipUpdated, "user", "user"},
	{"PATCH", "/organizations/:organization/users/:user", UserUpdated, "user", "user"},
	{"POST", "/organizations/:organization/groups", GroupCreated, "group", ""},
	{"PATCH", "/organizations/:organization/groups/:group", GroupUpdated, "group", "group"},
	{"DELETE", "/organizations/:organization/groups/:group", GroupDeleted, "group", "group"},
	{"POST", "/organizations/:organization/groups/:group/members", GroupMembersChanged, "group", "group"},
	{"POST", "/organizations/:organization/domains/:domain", DomainCreated, "domain", "domain"},
	{"POST", "/organizations/:organization/domains/:domain/verify", DomainVerified, "domain", "domain"},
	{"POST", "/organizations/:organization/domains/:domain/force-verify", DomainVerified, "domain", "domain"},
	{"DELETE", "/organizations/:organization/domains/:domain", DomainDeleted, "domain", "domain"},
	{"POST", "/organizations/:organization/org-units", OrgUnitCreated, "org_unit", ""},
	{"PUT", "/organizations/:organization/org-units/:org_unit", OrgUnitUpdated, "org_unit", "org_unit"},
	{"DELETE", "/organizations/:organization/org-units/:org_unit", OrgUnitDeleted, "org_unit", "org_unit"},
	{"POST", "/organizations/:organization/positions", PositionCreated, "position", ""},
	{"PUT", "/organizations/:organization/positions/:position", PositionUpdated, "position", "position"},
	{"DELETE", "/organizations/:organization/positions/:position", PositionDeleted, "position", "position"},
	{"POST", "/organizations/:organization/position-assignments", PositionAssigned, "position_assignment", ""},
	{"DELETE", "/organizations/:organization/position-assignments/:assignment", PositionUnassigned, "position_assignment", "assignment"},
	{"POST", "/organizations/:organization/role-assignments", RoleAssigned, "user", ""},
	{"DELETE", "/organizations/:organization/role-assignments/:user/:role", RoleUnassigned, "user", "user"},
	{"PUT", "/organizations/:organization/resource-grants", ResourceGrantUpdated, "resource_grant", ""},
	{"DELETE", "/organizations/:organization/resource-grants/:resource_grant", ResourceGrantDeleted, "resource_grant", "resource_grant"},
	{"POST", "/organizations/:organization/connections/:connection", ConnectionCreated, "connection", "connection"},
	{"PATCH", "/organizations/:organization/connections/:connection", ConnectionUpdated, "connection", "connection"},
	{"DELETE", "/organizations/:organization/connections/:connection", ConnectionDisabled, "connection", "connection"},
	{"PUT", "/organizations/:organization/branding", BrandingUpdated, "organization", "organization"},
	{"DELETE", "/organizations/:organization/branding", BrandingDeleted, "organization", "organization"},
	{"PATCH", "/applications/:application", ApplicationUpdated, "application", "application"},
	{"PATCH", "/oauth-clients/:client", OAuthClientUpdated, "oauth_client", "client"},
	{"DELETE", "/oauth-clients/:client", OAuthClientDisabled, "oauth_client", "client"},
	{"POST", "/logout-deliveries/:delivery/retry", LogoutDeliveryRetried, "logout_delivery", "delivery"},
	{"PUT", "/resources/:resource", ResourceUpdated, "resource", "resource"},
	{"PUT", "/resources/:resource/access", ResourceAccessUpdated, "resource", "resource"},
	{"PUT", "/resource-grants", ResourceGrantUpdated, "resource_grant", ""},
	{"DELETE", "/resource-grants/:resource_grant", ResourceGrantDeleted, "resource_grant", "resource_grant"},
	{"POST", "/roles", RoleCreated, "role", ""},
	{"PUT", "/roles/:role", RoleUpdated, "role", "role"},
	{"DELETE", "/roles/:role", RoleDeleted, "role", "role"},
	{"POST", "/role-assignments", RoleAssigned, "user", ""},
	{"DELETE", "/role-assignments/:role/:organization/:user", RoleUnassigned, "user", "user"},
	{"POST", "/group-role-assignments", GroupRoleAssigned, "group", ""},
	{"DELETE", "/group-role-assignments/:role/:organization/:group", GroupRoleUnassigned, "group", "group"},
	{"POST", "/federation-connections/:connection", ConnectionCreated, "connection", "connection"},
	{"PATCH", "/federation-connections/:connection", ConnectionUpdated, "connection", "connection"},
	{"DELETE", "/federation-connections/:connection", ConnectionDisabled, "connection", "connection"},
	{"POST", "/external-identities", IdentityLinked, "user", ""},
	{"DELETE", "/external-identities/:connection/:user", IdentityUnlinked, "user", "user"},
	{"POST", "/provisioning-credentials/:credential", ProvisioningCredentialCreated, "provisioning_credential", "credential"},
	{"DELETE", "/provisioning-credentials/:credential", ProvisioningCredentialRevoked, "provisioning_credential", "credential"},
	{"POST", "/provisioned-identities", ProvisioningIdentityLinked, "user", ""},
	{"PUT", "/login-settings", BrandingUpdated, "environment", ""},
	{"PUT", "/login-settings/clients/:client", BrandingUpdated, "oauth_client", "client"},
	{"DELETE", "/login-settings/clients/:client", BrandingDeleted, "oauth_client", "client"},
	{"PUT", "/login-settings/clients/:client/sign-in", SignInOptionsUpdated, "oauth_client", "client"},
	{"DELETE", "/login-settings/clients/:client/sign-in", SignInOptionsDeleted, "oauth_client", "client"},
	{"PUT", "/login-settings/organizations/:organization", BrandingUpdated, "organization", "organization"},
	{"DELETE", "/login-settings/organizations/:organization", BrandingDeleted, "organization", "organization"},
	{"PUT", "/login-settings/texts/:locale", SignInTextsUpdated, "environment", ""},
	{"DELETE", "/login-settings/texts/:locale", SignInTextsDeleted, "environment", ""},
	{"PUT", "/login-settings/clients/:client/texts/:locale", SignInTextsUpdated, "oauth_client", "client"},
	{"DELETE", "/login-settings/clients/:client/texts/:locale", SignInTextsDeleted, "oauth_client", "client"},
	{"PUT", "/login-settings/organizations/:organization/texts/:locale", SignInTextsUpdated, "organization", "organization"},
	{"DELETE", "/login-settings/organizations/:organization/texts/:locale", SignInTextsDeleted, "organization", "organization"},
	{"PUT", "/features/:feature", FeatureUpdated, "feature", "feature"},
	{"DELETE", "/features/:feature", FeatureReset, "feature", "feature"},
	{"PUT", "/limits", LimitsUpdated, "environment", ""},
	{"DELETE", "/sessions/:session", "", "", ""},
}

type named struct{ typ, kind string }

// actions maps the semantic audit actions to event types and subject
// kinds. The subject id is the target when it is a bare id, the user of a
// ?user= target for user subjects, else the target path's last UUID.
var actions = map[string]named{
	"user.signup":                         {UserSignedUp, "user"},
	"user.deactivated":                    {UserDeactivated, "user"},
	"user.reactivated":                    {UserReactivated, "user"},
	"user.locked":                         {UserLocked, "user"},
	"user.unlocked":                       {UserUnlocked, "user"},
	"user.profile_updated":                {UserProfileUpdated, "user"},
	"user.metadata_set":                   {UserMetadataSet, "user"},
	"user.metadata_deleted":               {UserMetadataDeleted, "user"},
	"user.phone_verified":                 {UserPhoneVerified, "user"},
	"user.phone_verified_set":             {UserPhoneVerified, "user"},
	"user.phone_removed":                  {UserPhoneRemoved, "user"},
	"user.access_token_created":           {UserAccessTokenCreated, "user"},
	"user.access_token_revoked":           {UserAccessTokenRevoked, "user"},
	"user.key_added":                      {UserKeyAdded, "user"},
	"user.key_removed":                    {UserKeyRemoved, "user"},
	"user.schema_updated":                 {UserSchemaUpdated, "environment"},
	"user.schema_deleted":                 {UserSchemaDeleted, "environment"},
	"federation.profile_updated":          {UserProfileSynced, "user"},
	"federation.email":                    {IdentityLinked, "user"},
	"federation.jit":                      {IdentityLinked, "user"},
	"federation.signup":                   {IdentityLinked, "user"},
	"organization.metadata_set":           {OrganizationMetadataSet, "organization"},
	"organization.metadata_deleted":       {OrganizationMetadataDeleted, "organization"},
	"mfa.enrolled":                        {MFAEnrolled, "user"},
	"mfa.removed":                         {MFARemoved, "user"},
	"mfa.reset":                           {MFAReset, "user"},
	"mfa.locked":                          {MFALocked, "user"},
	"mfa.recovery_used":                   {MFARecoveryUsed, "user"},
	"mfa.recovery_regenerated":            {MFARecoveryRegenerated, "user"},
	"mfa.clone_detected":                  {MFACloneDetected, "user"},
	"invitation.create":                   {InvitationCreated, "invitation"},
	"invitation.resend":                   {InvitationResent, "invitation"},
	"invitation.revoke":                   {InvitationRevoked, "invitation"},
	"invitation.accept":                   {InvitationAccepted, "invitation"},
	"impersonate":                         {ImpersonationStarted, "session"},
	"oauth.impersonated":                  {ImpersonationStarted, "session"},
	"oauth.token_exchanged":               {TokenExchanged, "session"},
	"oauth.device_approved":               {DeviceApproved, "session"},
	"oauth.backchannel_failed":            {LogoutDeliveryFailed, "oauth_client"},
	"saml.assertion_issued":               {SAMLAssertionIssued, "saml_service_provider"},
	"saml_service_provider.create":        {SAMLServiceProviderCreated, "saml_service_provider"},
	"saml_service_provider.update":        {SAMLServiceProviderUpdated, "saml_service_provider"},
	"saml_service_provider.delete":        {SAMLServiceProviderDeleted, "saml_service_provider"},
	"signing_key.create":                  {SigningKeyCreated, "signing_key"},
	"signing_key.activate":                {SigningKeyActivated, "signing_key"},
	"signing_key.retire":                  {SigningKeyRetired, "signing_key"},
	"action_target.create":                {ActionTargetCreated, "action_target"},
	"action_target.update":                {ActionTargetUpdated, "action_target"},
	"action_target.delete":                {ActionTargetDeleted, "action_target"},
	"action_target.rotate_secret":         {ActionTargetSecretRotated, "action_target"},
	"action_execution.set":                {ActionExecutionUpdated, "action_execution"},
	"action_execution.delete":             {ActionExecutionDeleted, "action_execution"},
	"service_account.authentication":      {ServiceAccountUpdated, "service_account"},
	"service_account.impersonation":       {ServiceAccountUpdated, "service_account"},
	"org_admin_portal.enabled":            {OrgAdminPortalEnabled, "oauth_client"},
	"org_admin_portal.disabled":           {OrgAdminPortalDisabled, "oauth_client"},
	"delivery.update":                     {DeliveryUpdated, "environment"},
	"delivery.delete":                     {DeliveryDeleted, "environment"},
	"delivery.test":                       {DeliveryTested, "environment"},
	"email_template.updated":              {EmailTemplateUpdated, "environment"},
	"email_template.reset":                {EmailTemplateDeleted, "environment"},
	"sms.update":                          {SMSUpdated, "environment"},
	"sms.delete":                          {SMSDeleted, "environment"},
	"sms.test":                            {SMSTested, "environment"},
	"password_policy.update":              {PasswordPolicyUpdated, "environment"},
	"password_policy.delete":              {PasswordPolicyDeleted, "environment"},
	"organization_password_policy.update": {PasswordPolicyUpdated, "organization"},
	"organization_password_policy.delete": {PasswordPolicyDeleted, "organization"},
	"sign_in_policy.update":               {SignInPolicyUpdated, "environment"},
	"sign_in_policy.delete":               {SignInPolicyDeleted, "environment"},
	ActionWebhookCreate:                   {WebhookCreated, "webhook"},
	ActionWebhookUpdate:                   {WebhookUpdated, "webhook"},
	ActionWebhookDelete:                   {WebhookDeleted, "webhook"},
	ActionWebhookRotate:                   {WebhookSecretRotated, "webhook"},
	ActionWebhookReplay:                   {WebhookReplayed, "webhook"},
	ActionWebhookRetry:                    {WebhookDeliveryRetried, "webhook"},
	ActionWebhookDisable:                  {WebhookDisabled, "webhook"},
	// Ends a session: the trigger writes session.revoked.
	"oauth.logout": {},
}

const uuidPattern = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

var (
	envPrefix    = regexp.MustCompile(`^(/management/v1|/api/v1)?/environments/` + uuidPattern)
	orgAdmin     = regexp.MustCompile(`^(/organizations/` + uuidPattern + `)/admin(/|$)`)
	lastUUID     = regexp.MustCompile(`.*(` + uuidPattern + `)`)
	organization = regexp.MustCompile(`/organizations/(` + uuidPattern + `)`)
	connection   = regexp.MustCompile(`/federation-connections/(` + uuidPattern + `)`)
	template     = regexp.MustCompile(`/templates/([a-z_]+)/([A-Za-z-]+)$`)
)

// Classify turns an audit entry into its semantic event. ok is false for
// entries that describe no event of their own (unknown actions, session
// ends the triggers already record).
func Classify(action, target string) (Classified, bool) {
	path, raw, _ := strings.Cut(target, "?")
	data := map[string]any{}
	if q, err := url.ParseQuery(raw); err == nil {
		for k, v := range q {
			if len(v) > 0 && ValidPrefix(k) {
				data[k] = v[0]
			}
		}
	}
	if m := organization.FindStringSubmatch(path); m != nil {
		data["organization_id"] = strings.ToLower(m[1])
	}
	switch action {
	case "POST", "PUT", "PATCH", "DELETE":
		return classifyRoute(action, path, data)
	}
	n, ok := actions[action]
	if !ok || n.typ == "" {
		return Classified{}, false
	}
	out := Classified{Type: n.typ, Subject: Subject{Kind: n.kind}, Data: data}
	if origin, ok := strings.CutPrefix(action, "federation."); ok && n.typ == IdentityLinked {
		data["origin"] = origin
		if m := connection.FindStringSubmatch(path); m != nil {
			data["connection_id"] = strings.ToLower(m[1])
		}
	}
	if m := template.FindStringSubmatch(path); m != nil {
		data["purpose"], data["locale"] = m[1], m[2]
	}
	if n.kind == "service_account" {
		data["setting"] = strings.TrimPrefix(action, "service_account.")
	}
	user, _ := data["user"].(string)
	switch {
	case n.kind == "environment":
	case n.kind == "organization" && data["organization_id"] != nil:
		out.Subject.ID = data["organization_id"].(string)
	case n.kind == "user" && user != "":
		out.Subject.ID = user
	case path != "" && !strings.Contains(path, "/"):
		out.Subject.ID = path
	default:
		if m := lastUUID.FindStringSubmatch(path); m != nil {
			out.Subject.ID = strings.ToLower(m[1])
		}
	}
	if user != "" {
		delete(data, "user")
		data["user_id"] = user
	}
	return out, true
}

func classifyRoute(method, path string, data map[string]any) (Classified, bool) {
	path = envPrefix.ReplaceAllString(path, "")
	path = orgAdmin.ReplaceAllString(path, "$1$2")
	path = strings.TrimSuffix(path, "/")
	for _, r := range routes {
		if r.method != method {
			continue
		}
		params, ok := match(r.pattern, path)
		if !ok {
			continue
		}
		if r.typ == "" {
			return Classified{}, false
		}
		for k, v := range params {
			data[k+"_id"] = v
		}
		out := Classified{Type: r.typ, Subject: Subject{Kind: r.kind}, Data: data}
		if r.param != "" {
			out.Subject.ID = params[r.param]
			delete(data, r.param+"_id")
		}
		return out, true
	}
	return Classified{}, false
}

// match compares a route pattern with a path segment by segment; :name
// segments capture any non-empty value.
func match(pattern, path string) (map[string]string, bool) {
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	xs := strings.Split(strings.Trim(path, "/"), "/")
	if len(ps) != len(xs) {
		return nil, false
	}
	params := map[string]string{}
	for i, p := range ps {
		if name, ok := strings.CutPrefix(p, ":"); ok {
			if xs[i] == "" {
				return nil, false
			}
			params[name] = strings.ToLower(xs[i])
			continue
		}
		if p != xs[i] {
			return nil, false
		}
	}
	return params, true
}
