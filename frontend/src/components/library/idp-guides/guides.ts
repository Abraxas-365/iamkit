import { t } from '@/lib/i18n'

/** The IAMKit values a step asks the administrator to copy into the identity
 * provider (or, for SCIM, into the directory). */
export type GuideValue = 'acs' | 'entity_id' | 'metadata_url' | 'redirect_uri' | 'scim_url' | 'scim_token'

export interface GuideStep { title: string; body: string; values?: GuideValue[] }

export interface Guide {
  id: string
  label: string
  protocol: 'saml' | 'oidc' | 'ldap' | 'scim'
  /** OIDC only: the connection provider the guide creates ('oidc' when absent). */
  preset?: 'oidc' | 'microsoft' | 'google'
  steps: GuideStep[]
  /** What the identity provider must send, as [name, value] rows. */
  attributes: [string, string][]
  troubleshooting: { problem: string; fix: string }[]
}

// The menu paths follow each vendor's admin UI as documented when this guide
// was written; vendors rename screens, so steps stay at the level of "go to X,
// choose Y" and say what to look for rather than pixel-exact instructions.

const samlAttributes: [string, string][] = [
  [t('NameID'), t('Email address (format: emailAddress), or a persistent ID')],
  ['email', t('The user\'s email address')],
  ['displayName', t('The user\'s full name (optional)')],
  ['groups', t('The user\'s groups, one value each (optional, for group mapping)')],
]

const samlTroubleshooting = [
  { problem: t('The test page says the signature is invalid'), fix: t('The metadata IAMKit holds is out of date or from another application. Paste the metadata of this exact application again.') },
  { problem: t('The test page shows no email'), fix: t('Release the user\'s email as an attribute named email, or set the NameID format to email address.') },
  { problem: t('The identity provider says the audience or ACS URL does not match'), fix: t('Copy the entity ID and the ACS URL again, without trailing spaces. They are case-sensitive.') },
  { problem: t('The user is not allowed to sign in'), fix: t('Assign the user (or one of their groups) to the application in the identity provider.') },
]

const oidcTroubleshooting = [
  { problem: t('The provider says the redirect URI does not match'), fix: t('Register the redirect URI exactly as shown, including https:// and the path.') },
  { problem: t('The test page reports an invalid client or secret'), fix: t('Check the client ID and create a new client secret; copy its value, not its ID.') },
  { problem: t('The test page shows no email or the email is not verified'), fix: t('Grant the email and profile scopes. Only a verified email can link or create accounts.') },
  { problem: t('The issuer is rejected'), fix: t('The issuer must be the HTTPS URL that serves /.well-known/openid-configuration, with no trailing path added.') },
]

export const samlGuides: Guide[] = [
  {
    id: 'okta-saml', label: t('Okta'), protocol: 'saml',
    steps: [
      { title: t('Create the application'), body: t('In the Okta Admin Console go to Applications → Applications → Create App Integration, choose SAML 2.0 and name the application.') },
      { title: t('Enter the IAMKit values'), body: t('On Configure SAML paste the values below: the ACS URL goes in Single sign-on URL and the entity ID in Audience URI (SP Entity ID). Set Name ID format to EmailAddress and Application username to Email.'), values: ['acs', 'entity_id'] },
      { title: t('Add attribute statements'), body: t('Under Attribute Statements add email → user.email and displayName → user.displayName. To map groups, add a Group Attribute Statement named groups with a filter.') },
      { title: t('Copy the metadata'), body: t('Finish the wizard, open the Sign On tab and copy the Metadata URL of the identity provider. You paste it in the next step of this guide.') },
      { title: t('Assign people'), body: t('On the Assignments tab assign the people or groups who may sign in.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'entra-saml', label: t('Microsoft Entra ID'), protocol: 'saml',
    steps: [
      { title: t('Create the application'), body: t('In the Microsoft Entra admin center go to Enterprise applications → New application → Create your own application, and choose "Integrate any other application you don\'t find in the gallery (Non-gallery)".') },
      { title: t('Set up single sign-on'), body: t('Open Single sign-on → SAML. In Basic SAML Configuration paste the entity ID as Identifier (Entity ID) and the ACS URL as Reply URL (Assertion Consumer Service URL).'), values: ['entity_id', 'acs'] },
      { title: t('Check the claims'), body: t('In Attributes & Claims make sure the email claim is user.mail and the unique user identifier is the email or user principal name. Add a groups claim if you map groups (object IDs unless you change it).') },
      { title: t('Copy the metadata'), body: t('In SAML Certificates copy the App Federation Metadata Url. You paste it in the next step of this guide.') },
      { title: t('Assign people'), body: t('On Users and groups assign the users and groups who may sign in.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'google-saml', label: t('Google Workspace'), protocol: 'saml',
    steps: [
      { title: t('Add a custom SAML app'), body: t('In the Google Admin console go to Apps → Web and mobile apps → Add app → Add custom SAML app and name it.') },
      { title: t('Download the metadata'), body: t('On Google Identity Provider details choose Download Metadata. Google gives a file, not a URL: you paste its XML in the next step of this guide.') },
      { title: t('Enter the IAMKit values'), body: t('On Service provider details paste the ACS URL and the entity ID. Set Name ID format to EMAIL and Name ID to Basic Information → Primary email.'), values: ['acs', 'entity_id'] },
      { title: t('Map attributes'), body: t('Optionally map Primary email → email and the full name → displayName on Attribute mapping.') },
      { title: t('Turn the app on'), body: t('Open the app\'s User access and turn it ON for the organizational units or groups who may sign in.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'onelogin-saml', label: t('OneLogin'), protocol: 'saml',
    steps: [
      { title: t('Create the application'), body: t('In the OneLogin admin portal go to Applications → Applications → Add App and pick "SAML Custom Connector (Advanced)".') },
      { title: t('Enter the IAMKit values'), body: t('On Configuration paste the entity ID as Audience (EntityID) and the ACS URL as ACS (Consumer) URL. Use the ACS URL for the Recipient too, and the ACS URL Validator as a regular expression matching it.'), values: ['entity_id', 'acs'] },
      { title: t('Set the NameID and parameters'), body: t('Set SAML nameID format to Email and add an email parameter mapped to Email, plus optional name and groups parameters.') },
      { title: t('Copy the metadata'), body: t('Save, then use More Actions → SAML Metadata to download the XML (or copy the Issuer URL from the SSO tab). You paste the XML in the next step of this guide.') },
      { title: t('Assign people'), body: t('On Users or Roles give the people who may sign in access to the app.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'jumpcloud-saml', label: t('JumpCloud'), protocol: 'saml',
    steps: [
      { title: t('Create the application'), body: t('In the JumpCloud Admin Portal go to SSO Applications, add a new application and choose Custom SAML App.') },
      { title: t('Enter the IAMKit values'), body: t('On the SSO tab paste the entity ID as SP Entity ID and the ACS URL as ACS URL. Set SAMLSubject NameID to email.'), values: ['entity_id', 'acs'] },
      { title: t('Add attributes'), body: t('Add the attributes email and displayName, and a groups attribute if you map groups.') },
      { title: t('Copy the metadata'), body: t('Save the application and export its metadata (Export Metadata). You paste the XML in the next step of this guide.') },
      { title: t('Assign people'), body: t('On the User Groups tab connect the groups who may sign in.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'adfs-saml', label: t('ADFS'), protocol: 'saml',
    steps: [
      { title: t('Add a relying party trust'), body: t('In AD FS Management go to Relying Party Trusts → Add Relying Party Trust, choose Claims aware, and import the data about the relying party from the metadata URL below (or enter it manually with the entity ID and ACS URL).'), values: ['metadata_url', 'entity_id', 'acs'] },
      { title: t('Send the email as the NameID'), body: t('Edit Claim Issuance Policy. Add Send LDAP Attributes as Claims (E-Mail-Addresses → E-Mail Address, and Display-Name → Name), then Transform an Incoming Claim: E-Mail Address → Name ID with format Email.') },
      { title: t('Copy the metadata URL'), body: t('The federation metadata of your ADFS server is at https://<your ADFS host>/FederationMetadata/2007-06/FederationMetadata.xml. You paste it in the next step of this guide.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'ping-saml', label: t('PingFederate'), protocol: 'saml',
    steps: [
      { title: t('Create an SP connection'), body: t('In the PingFederate administrative console create a new SP connection for Browser SSO (Applications → Integration → SP Connections → Create Connection). You can import the IAMKit metadata from the URL below instead of typing the values.'), values: ['metadata_url', 'entity_id', 'acs'] },
      { title: t('Configure Browser SSO'), body: t('Use the POST binding for the Assertion Consumer Service URL and the entity ID as the connection\'s Partner Entity ID. Extend the attribute contract with email, displayName and optionally groups.') },
      { title: t('Choose the signing certificate'), body: t('Select the signing certificate and keep the assertion signed (or the whole response).') },
      { title: t('Export your metadata'), body: t('Export the metadata of your PingFederate server (or of this connection) and paste its XML, or its URL if you publish one, in the next step of this guide.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
  {
    id: 'generic-saml', label: t('Generic SAML'), protocol: 'saml',
    steps: [
      { title: t('Create a SAML application'), body: t('In your identity provider create a custom SAML 2.0 application (service provider).') },
      { title: t('Enter the IAMKit values'), body: t('Give it the values below: the ACS URL (HTTP-POST binding) and the entity ID (audience). If it can import service provider metadata, give it the metadata URL instead.'), values: ['acs', 'entity_id', 'metadata_url'] },
      { title: t('Release the user\'s attributes'), body: t('Send the email as the NameID (format emailAddress) or as an email attribute, and optionally displayName and groups.') },
      { title: t('Copy the identity provider metadata'), body: t('Copy its metadata URL, or download the XML. You paste it in the next step of this guide.') },
    ],
    attributes: samlAttributes, troubleshooting: samlTroubleshooting,
  },
]

const oidcAttributes: [string, string][] = [
  ['openid email profile', t('Scopes IAMKit requests')],
  ['email / email_verified', t('The user\'s email; only a verified email links or creates accounts')],
  ['name', t('The user\'s full name (optional)')],
  ['groups', t('The user\'s groups in the ID token (optional, for group mapping)')],
]

export const oidcGuides: Guide[] = [
  {
    id: 'okta-oidc', label: t('Okta (OIDC)'), protocol: 'oidc',
    steps: [
      { title: t('Create the application'), body: t('In the Okta Admin Console go to Applications → Applications → Create App Integration, choose OIDC - OpenID Connect and the application type Web Application.') },
      { title: t('Register the redirect URI'), body: t('Paste the value below as a Sign-in redirect URI and save the application.'), values: ['redirect_uri'] },
      { title: t('Assign people'), body: t('On the Assignments tab assign the people or groups who may sign in.') },
      { title: t('Copy the credentials'), body: t('Copy the Client ID and Client secret from the General tab. The issuer is your Okta domain, e.g. https://acme.okta.com (or the issuer of a custom authorization server). To send groups, add a groups claim to the ID token.') },
    ],
    attributes: oidcAttributes, troubleshooting: oidcTroubleshooting,
  },
  {
    id: 'entra-oidc', label: t('Microsoft Entra ID'), protocol: 'oidc', preset: 'microsoft',
    steps: [
      { title: t('Register the application'), body: t('In the Microsoft Entra admin center go to App registrations → New registration. Choose the supported account types and, as Redirect URI, the platform Web with the value below.'), values: ['redirect_uri'] },
      { title: t('Create a client secret'), body: t('Open Certificates & secrets → New client secret and copy its Value right away (not the Secret ID).') },
      { title: t('Copy the IDs'), body: t('From Overview copy the Application (client) ID and the Directory (tenant) ID. Use the tenant ID below to accept only your tenant.') },
    ],
    attributes: oidcAttributes, troubleshooting: oidcTroubleshooting,
  },
  {
    id: 'google-oidc', label: t('Google Workspace'), protocol: 'oidc', preset: 'google',
    steps: [
      { title: t('Configure the consent screen'), body: t('In the Google Cloud console go to APIs & Services → OAuth consent screen and choose the user type Internal so only your Workspace accounts can use it.') },
      { title: t('Create the OAuth client'), body: t('Go to APIs & Services → Credentials → Create credentials → OAuth client ID, choose Web application and add the value below as an Authorized redirect URI.'), values: ['redirect_uri'] },
      { title: t('Copy the credentials'), body: t('Copy the Client ID and the Client secret. List your Workspace domains below so only their accounts can sign in.') },
    ],
    attributes: oidcAttributes, troubleshooting: oidcTroubleshooting,
  },
  {
    id: 'generic-oidc', label: t('Generic OIDC'), protocol: 'oidc',
    steps: [
      { title: t('Register a web application'), body: t('In your OpenID Connect provider create a confidential web client using the authorization code flow.') },
      { title: t('Register the redirect URI'), body: t('Add the value below as an allowed redirect URI.'), values: ['redirect_uri'] },
      { title: t('Copy the credentials'), body: t('Copy the issuer URL (the one that serves /.well-known/openid-configuration), the client ID and the client secret.') },
    ],
    attributes: oidcAttributes, troubleshooting: oidcTroubleshooting,
  },
]

export const ldapGuide: Guide = {
  id: 'ldap', label: t('LDAP / Active Directory'), protocol: 'ldap',
  steps: [
    { title: t('Make the directory reachable'), body: t('IAMKit connects over ldaps:// (port 636) or ldap:// with StartTLS. It must reach the server; private addresses need the server administrator to allow the host.') },
    { title: t('Create a service account'), body: t('Create a read-only account (for example CN=iamkit,OU=Service Accounts,DC=example,DC=com) that can search the users\' subtree. Anonymous search also works if the directory allows it.') },
    { title: t('Find the users'), body: t('Choose the base DN that holds your users and a filter that matches exactly one entry, e.g. (sAMAccountName={username}) for Active Directory or (mail={email}).') },
  ],
  attributes: [
    ['objectGUID / entryUUID', t('The stable user ID')],
    ['mail / userPrincipalName', t('The user\'s email')],
    ['displayName', t('The user\'s full name')],
    ['memberOf', t('The user\'s groups (optional)')],
  ],
  troubleshooting: [
    { problem: t('The connection is refused'), fix: t('Check the URL and port, the CA certificate for a private CA, and that IAMKit can reach the host.') },
    { problem: t('Users are not found'), fix: t('Check the base DN and the filter; it must match exactly one entry for the typed email or username.') },
  ],
}

export const scimGuides: Guide[] = [
  {
    id: 'okta-scim', label: t('Okta (SCIM)'), protocol: 'scim',
    steps: [
      { title: t('Add a SCIM application'), body: t('In the Okta Admin Console add an application that supports SCIM provisioning (for example from the catalog, "SCIM 2.0 Test App (Header Auth)"), or enable provisioning on your SAML application.') },
      { title: t('Configure the API integration'), body: t('Open Provisioning → Integration → Configure API Integration. Paste the SCIM base URL as SCIM connector base URL, set the unique identifier field to userName, and choose HTTP Header authentication with the token below.'), values: ['scim_url', 'scim_token'] },
      { title: t('Test and enable'), body: t('Choose Test API Credentials, save, then under Provisioning → To App enable Create Users, Update User Attributes and Deactivate Users.') },
    ],
    attributes: [['userName', t('The user\'s email')], ['externalId', t('A stable ID from your directory')]],
    troubleshooting: [{ problem: t('The test fails with 401'), fix: t('Paste the token without spaces. A revoked or expired token must be replaced with a new one.') }],
  },
  {
    id: 'entra-scim', label: t('Microsoft Entra ID (SCIM)'), protocol: 'scim',
    steps: [
      { title: t('Open provisioning'), body: t('In the Microsoft Entra admin center open the enterprise application and go to Provisioning (create the application first with New application → Create your own application if needed). Set Provisioning Mode to Automatic.') },
      { title: t('Enter the credentials'), body: t('Under Admin Credentials paste the SCIM base URL as Tenant URL and the token as Secret Token, then choose Test Connection.'), values: ['scim_url', 'scim_token'] },
      { title: t('Start provisioning'), body: t('Save, review the attribute mappings, assign users and groups, and set Provisioning Status to On.') },
    ],
    attributes: [['userPrincipalName → userName', t('The user\'s email')], ['objectId → externalId', t('A stable ID from your directory')]],
    troubleshooting: [{ problem: t('Test Connection fails'), fix: t('Paste the Tenant URL and the token again; a token that expired or was revoked must be replaced.') }],
  },
]

export const guideLabel = (value: GuideValue) => ({
  acs: t('ACS URL (HTTP-POST)'), entity_id: t('SP entity ID (audience)'), metadata_url: t('SP metadata URL'),
  redirect_uri: t('Redirect URI'), scim_url: t('SCIM base URL'), scim_token: t('Bearer token (Secret token)'),
}[value])
