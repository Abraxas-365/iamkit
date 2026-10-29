package event

// The event type catalog. Types are <family>.<past-tense verb>. Every
// event carries its subject's id and the ids of related entities in Data
// (organization_id, user_id, role_id, …) — never secrets or whole records:
// read the current state through the API. New types may appear in any
// release; consumers must ignore types they do not know.
const (
	UserCreated     = "user.created"
	UserUpdated     = "user.updated"
	UserDeactivated = "user.deactivated"
	UserReactivated = "user.reactivated"
	UserDeleted     = "user.deleted"
	UserLocked      = "user.locked"
	UserUnlocked    = "user.unlocked"
	// UserSessionsRevoked: an operator signed the user out everywhere, or
	// the user ended their other sessions (actor = the user); data.count
	// sessions ended.
	UserSessionsRevoked = "user.sessions_revoked"
	// UserPasswordChangeRequired: the next password sign-in must choose a
	// new password.
	UserPasswordChangeRequired = "user.password_change_required"
	// UserPasswordChanged: the user set a new password (data.method:
	// sign_in — expired or required at sign-in —, reset, or self_service —
	// POST /identity/v1/me/password).
	UserPasswordChanged = "user.password_changed"
	// UserOrganizationSwitched: a session was refreshed into another
	// organization of the user (data.from, data.to).
	UserOrganizationSwitched = "user.organization_switched"
	UserSignedUp             = "user.signed_up"
	UserProfileUpdated       = "user.profile_updated"
	UserProfileSynced        = "user.profile_synced"
	UserMetadataSet          = "user.metadata_set"
	UserMetadataDeleted      = "user.metadata_deleted"
	// UserProvisioned: a SCIM directory took over an existing user
	// (data.mode: claimed, reactivated, adopted); UserDeprovisioned: SCIM
	// DELETE removed the user from the directory's organization.
	UserProvisioned   = "user.provisioned"
	UserDeprovisioned = "user.deprovisioned"
	UserPhoneVerified = "user.phone_verified"
	UserPhoneRemoved  = "user.phone_removed"
	UserKeyAdded      = "user.key_added"
	UserKeyRemoved    = "user.key_removed"
	UserSchemaUpdated = "user_schema.updated"
	UserSchemaDeleted = "user_schema.deleted"

	OrganizationCreated         = "organization.created"
	OrganizationUpdated         = "organization.updated"
	OrganizationMetadataSet     = "organization.metadata_set"
	OrganizationMetadataDeleted = "organization.metadata_deleted"

	MembershipCreated = "membership.created"
	MembershipUpdated = "membership.updated"
	MembershipRemoved = "membership.removed"

	GroupCreated        = "group.created"
	GroupUpdated        = "group.updated"
	GroupDeleted        = "group.deleted"
	GroupMembersChanged = "group.members_changed"

	DomainCreated  = "domain.created"
	DomainVerified = "domain.verified"
	DomainDeleted  = "domain.deleted"

	OrgUnitCreated     = "org_unit.created"
	OrgUnitUpdated     = "org_unit.updated"
	OrgUnitDeleted     = "org_unit.deleted"
	PositionCreated    = "position.created"
	PositionUpdated    = "position.updated"
	PositionDeleted    = "position.deleted"
	PositionAssigned   = "position.assigned"
	PositionUnassigned = "position.unassigned"

	ApplicationCreated  = "application.created"
	ApplicationUpdated  = "application.updated"
	ApplicationLinked   = "application.resource_linked"
	ApplicationUnlinked = "application.resource_unlinked"

	OAuthClientCreated  = "oauth_client.created"
	OAuthClientUpdated  = "oauth_client.updated"
	OAuthClientDisabled = "oauth_client.disabled"
	// OAuthClientDiscovered: a client identified by a metadata document URL
	// asked for a protected resource for the first time (actor system;
	// data: client_id URL, protected_resource_id, admission).
	OAuthClientDiscovered = "oauth_client.discovered"
	// OAuthClientAccessRequested: a signed-in user asked for a client
	// identified by a metadata document that IT has not approved (actor the
	// user, at most one per client and user per
	// config.ClientAccessRequestInterval; data: client_id URL, host,
	// protected_resource_id, user_id, organization_id). Nothing is written
	// before the sign-in: anonymous requests leave no row and no event.
	OAuthClientAccessRequested = "oauth_client.access_requested"
	// OAuthClientApproved: IT approved an external client for a protected
	// resource (actor the operator; data: protected_resource_id,
	// admission_source, expires_at). An allowlist entry created later also
	// approves the pending clients it matches (source allowlist or preset).
	OAuthClientApproved = "oauth_client.approved"
	// OAuthClientBlocked: IT blocked an external client; its token
	// families and sessions were revoked in the same transaction
	// (data: protected_resource_id, revoked_sessions).
	OAuthClientBlocked = "oauth_client.blocked"
	// OAuthClientUnblocked: a blocked external client waits for IT again.
	OAuthClientUnblocked = "oauth_client.unblocked"
	// OAuthClientExpired: an approval reached its expiry; the
	// client_admission_expire job revoked its grants and the client waits
	// for IT again (actor system).
	OAuthClientExpired = "oauth_client.expired"
	// OAuthClientDemoted: an approved external client lost its approval
	// because the policy behind it ended (actor the operator, or system for
	// the reconcile job; data: protected_resource_id, reason, admission_source
	// = how it had been approved). Its grants were revoked in the same
	// transaction and it waits for IT again. reason is one of
	// oauth.Demotion*.
	OAuthClientDemoted = "oauth_client.demoted"
	// OAuthClientForgotten: IT deleted an external client with its grants;
	// it is discovered afresh if it asks again.
	OAuthClientForgotten = "oauth_client.forgotten"
	// OAuthClientAllowlist*: an allowlist entry admitting client metadata
	// documents without review was created or deleted (data: origin,
	// path_prefix, preset, protected_resource_id).
	OAuthClientAllowlistCreated = "oauth_client_allowlist.created"
	OAuthClientAllowlistDeleted = "oauth_client_allowlist.deleted"
	OrgAdminPortalEnabled       = "org_admin_portal.enabled"
	OrgAdminPortalDisabled      = "org_admin_portal.disabled"
	// OrgSetupLink*: an organization setup link was created or revoked
	// (actor: the operator or owner) or exchanged for a session (actor: the
	// link itself); subject = the link.
	OrgSetupLinkCreated   = "org_setup_link.created"
	OrgSetupLinkUsed      = "org_setup_link.used"
	OrgSetupLinkRevoked   = "org_setup_link.revoked"
	LogoutDeliveryFailed  = "logout_delivery.failed"
	LogoutDeliveryRetried = "logout_delivery.retried"

	ResourceCreated       = "resource.created"
	ResourceUpdated       = "resource.updated"
	ResourceAccessUpdated = "resource.access_updated"
	ResourceGrantUpdated  = "resource_grant.updated"
	ResourceGrantDeleted  = "resource_grant.deleted"

	RoleCreated         = "role.created"
	RoleUpdated         = "role.updated"
	RoleDeleted         = "role.deleted"
	RoleAssigned        = "role.assigned"
	RoleUnassigned      = "role.unassigned"
	GroupRoleAssigned   = "group_role.assigned"
	GroupRoleUnassigned = "group_role.unassigned"
	GrantUpdated        = "grant.updated"
	GrantDeleted        = "grant.deleted"

	ServiceAccountCreated = "service_account.created"
	ServiceAccountUpdated = "service_account.updated"
	ServiceAccountRevoked = "service_account.revoked"

	ConnectionCreated  = "connection.created"
	ConnectionUpdated  = "connection.updated"
	ConnectionDisabled = "connection.disabled"
	ConnectionEnabled  = "connection.enabled"
	// ConnectionTestRequested: an administrator issued a test sign-in link
	// for the connection (actor: whoever asked; data organization_id for
	// organization calls). Nothing is tested yet: connection.tested follows
	// when the sign-in ends.
	ConnectionTestRequested = "connection.test_requested"
	// ConnectionTested: a test sign-in of the connection ended (data
	// success, connection_id, organization_id; actor: whoever asked for
	// it). No session, user or link exists after it.
	ConnectionTested = "connection.tested"
	// ConnectionIdPInitiated: a verified IdP-initiated SAML response was
	// handed to the connection's OAuth client sign-in endpoint (no session).
	ConnectionIdPInitiated = "connection.idp_initiated"
	// ConnectionSingleLogout: the identity provider's signed LogoutRequest
	// ended the connection's sessions of a NameID (data.count; actor
	// system).
	ConnectionSingleLogout = "connection.single_logout"
	IdentityLinked         = "identity.linked"
	IdentityUnlinked       = "identity.unlinked"

	ProvisioningCredentialCreated = "provisioning_credential.created"
	ProvisioningCredentialRevoked = "provisioning_credential.revoked"
	ProvisioningIdentityLinked    = "provisioning_identity.linked"

	InvitationCreated  = "invitation.created"
	InvitationResent   = "invitation.resent"
	InvitationRevoked  = "invitation.revoked"
	InvitationAccepted = "invitation.accepted"

	SessionCreated       = "session.created"
	SessionRevoked       = "session.revoked"
	LoginFailed          = "login.failed"
	ImpersonationStarted = "impersonation.started"
	TokenExchanged       = "token.exchanged"
	DeviceApproved       = "device.approved"
	SAMLAssertionIssued  = "saml.assertion_issued"
	// SAMLLogout: a SAML application's signed LogoutRequest ended the
	// session it named (actor = the user).
	SAMLLogout = "saml.logout"
	// SAMLLogoutFailed: a back-channel (SOAP) LogoutRequest to an
	// application gave up.
	SAMLLogoutFailed = "saml.logout_failed"

	MFAEnrolled            = "mfa.enrolled"
	MFARemoved             = "mfa.removed"
	MFAReset               = "mfa.reset"
	MFALocked              = "mfa.locked"
	MFARecoveryUsed        = "mfa.recovery_used"
	MFARecoveryRegenerated = "mfa.recovery_regenerated"
	MFACloneDetected       = "mfa.clone_detected"

	SAMLServiceProviderCreated = "saml_service_provider.created"
	SAMLServiceProviderUpdated = "saml_service_provider.updated"
	SAMLServiceProviderDeleted = "saml_service_provider.deleted"

	SigningKeyCreated   = "signing_key.created"
	SigningKeyActivated = "signing_key.activated"
	SigningKeyRetired   = "signing_key.retired"

	BrandingUpdated       = "branding.updated"
	BrandingDeleted       = "branding.deleted"
	SignInOptionsUpdated  = "sign_in_options.updated"
	SignInOptionsDeleted  = "sign_in_options.deleted"
	PasswordPolicyUpdated = "password_policy.updated"
	PasswordPolicyDeleted = "password_policy.deleted"
	SignInPolicyUpdated   = "sign_in_policy.updated"
	SignInPolicyDeleted   = "sign_in_policy.deleted"
	DeliveryUpdated       = "delivery.updated"
	DeliveryDeleted       = "delivery.deleted"
	DeliveryTested        = "delivery.tested"
	EmailTemplateUpdated  = "email_template.updated"
	EmailTemplateDeleted  = "email_template.deleted"
	SignInTextsUpdated    = "sign_in_texts.updated"
	SignInTextsDeleted    = "sign_in_texts.deleted"
	// FeatureUpdated / FeatureReset: an environment override of a feature
	// flag was set (data.enabled) or removed; subject = the flag name.
	FeatureUpdated = "feature.updated"
	FeatureReset   = "feature.reset"
	// LimitsUpdated: the environment's limits were replaced (data.limits:
	// the limits set, absent = the deployment's).
	LimitsUpdated = "limits.updated"

	SMSUpdated = "sms.updated"
	SMSDeleted = "sms.deleted"
	SMSTested  = "sms.tested"

	WebhookCreated         = "webhook.created"
	WebhookUpdated         = "webhook.updated"
	WebhookDeleted         = "webhook.deleted"
	WebhookSecretRotated   = "webhook.secret_rotated"
	WebhookReplayed        = "webhook.replayed"
	WebhookDeliveryRetried = "webhook.delivery_retried"
	// WebhookDisabled: the subscription failed for
	// config.EventWebhookDisableAfter and was turned off.
	WebhookDisabled = "webhook.disabled"

	// App audit log actions (the registered action catalog) and log
	// streams. App audit log events themselves never enter this log.
	AuditLogActionCreated = "audit_log_action.created"
	AuditLogActionUpdated = "audit_log_action.updated"
	AuditLogActionDeleted = "audit_log_action.deleted"
	LogStreamCreated      = "log_stream.created"
	LogStreamUpdated      = "log_stream.updated"
	LogStreamDeleted      = "log_stream.deleted"
	// LogStreamSecretRotated: an https stream's signing secret was
	// rotated (the previous one signs for config.EventWebhookSecretOverlap).
	LogStreamSecretRotated   = "log_stream.secret_rotated"
	LogStreamDeliveryRetried = "log_stream.delivery_retried"
	// LogStreamDisabled: the stream failed for
	// config.EventWebhookDisableAfter and was turned off.
	LogStreamDisabled = "log_stream.disabled"

	// API keys (user, organization and machine user keys); data carries
	// owner_type, user_id (user and machine keys), organization_id,
	// resource_id, name and permissions — never the value. A key revoked
	// because its owner's membership ended has actor system and
	// data.reason membership_ended.
	APIKeyCreated = "api_key.created"
	APIKeyRevoked = "api_key.revoked"
	// APIKeyPolicyUpdated: the environment's API key policy changed.
	APIKeyPolicyUpdated = "api_key_policy.updated"

	// Bot protection and risk signals. CaptchaUpdated / CaptchaDeleted:
	// the environment's CAPTCHA configuration (never the secret).
	CaptchaUpdated = "captcha.updated"
	CaptchaDeleted = "captcha.deleted"
	// RiskPolicyUpdated / RiskPolicyDeleted: the environment's risk policy
	// (deleted = back to every detection off).
	RiskPolicyUpdated = "risk_policy.updated"
	RiskPolicyDeleted = "risk_policy.deleted"
	// RiskRestrictionCreated / RiskRestrictionDeleted: an allow or deny
	// restriction (data kind, value, action).
	RiskRestrictionCreated = "risk_restriction.created"
	RiskRestrictionDeleted = "risk_restriction.deleted"
	// The sign-up waitlist: joined (actor system, data email_domain only —
	// never the address), approved / rejected / deleted (actor = the
	// operator), completed (the approved person created their account;
	// data user_id).
	WaitlistJoined    = "waitlist.joined"
	WaitlistApproved  = "waitlist.approved"
	WaitlistRejected  = "waitlist.rejected"
	WaitlistDeleted   = "waitlist.deleted"
	WaitlistCompleted = "waitlist.completed"
	// Protected resources (RFC 9728 resource servers, e.g. remote MCP
	// servers): created / updated / deleted (data uri, resource_id,
	// application_id); the environment's TTL ceilings changed
	// (protected_resource_policy.updated, data the ceilings and trimmed).
	ProtectedResourceCreated       = "protected_resource.created"
	ProtectedResourceUpdated       = "protected_resource.updated"
	ProtectedResourceDeleted       = "protected_resource.deleted"
	ProtectedResourcePolicyUpdated = "protected_resource_policy.updated"
	// RiskDetected: a sign-in fired detections whose action is log or
	// stronger; subject = the sign-in attempt, data user_id, detections,
	// action, outcome, ip, country, method, surface.
	RiskDetected = "risk.detected"
	// SignInBlocked: a deny restriction or a block detection refused a
	// sign-in (or signup); subject = the attempt, data reason
	// (restriction|detection), restriction_id or detections, ip, country.
	SignInBlocked = "sign_in.blocked"

	ActionTargetCreated       = "action_target.created"
	ActionTargetUpdated       = "action_target.updated"
	ActionTargetDeleted       = "action_target.deleted"
	ActionTargetSecretRotated = "action_target.secret_rotated"
	// ActionExecutionUpdated / ActionExecutionDeleted: the targets bound
	// to a condition were set or removed; subject = the condition.
	ActionExecutionUpdated = "action_execution.updated"
	ActionExecutionDeleted = "action_execution.deleted"
	// ActionFailed: a target failed (timeout, error status, invalid
	// response); data names the condition, target and whether the flow
	// was interrupted.
	ActionFailed = "action.failed"
)
