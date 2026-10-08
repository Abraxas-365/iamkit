// More fictional data for the buyer videos: people, applications, OAuth clients,
// sessions, service accounts, SCIM tokens, policies, keys, webhooks, usage.
// Spread over `api` in demo-data.mjs. Nothing here comes from a real deployment.
import { ENV, consoleSim, organizations, resources, social, sso, uuid } from './demo-data.mjs'

const BASE = `/environments/${ENV}`
const list = (items, total = items.length) => ({ items, page: { total, limit: 50, offset: 0 } })
const minutes = n => new Date(Date.parse('2026-10-07T17:00:00Z') - n * 60_000).toISOString()
const days = n => minutes(n * 1440)
const search = (items, url, keys = ['name', 'email']) => {
  const q = (url.searchParams.get('search') ?? '').toLowerCase()
  return q ? items.filter(i => keys.some(k => String(i[k] ?? '').toLowerCase().includes(q))) : items
}
const [acme, brightside, cobalt] = organizations
const [billing, projectsApi] = resources

// ── Users ──
const user = (name, slug, state = 'active', extra = {}) => ({
  id: uuid(`user-${name}`), name, email: `${name.split(' ')[0].toLowerCase()}@${slug}.example`, active: state !== 'suspended', state,
  email_verified: true, otp_enabled: true, last_signed_in_at: minutes(20), home_organization_id: acme.id, ...extra,
})
export const users = [
  user('Maya Chen', 'acme-logistics', 'active', { last_signed_in_at: minutes(1) }),
  user('Daniel Okafor', 'acme-logistics', 'active', { last_signed_in_at: minutes(34) }),
  user('Sofia Alvarez', 'acme-logistics', 'active', { last_signed_in_at: minutes(120) }),
  user('Tomás Berg', 'brightside', 'locked', { home_organization_id: brightside.id, failed_logins: 5, locked_until: minutes(-9), last_signed_in_at: minutes(3) }),
  user('Hannah Weiss', 'cobalt', 'active', { home_organization_id: cobalt.id, last_signed_in_at: minutes(12) }),
  user('Omar Haddad', 'brightside', 'initial', { home_organization_id: brightside.id, last_signed_in_at: null, otp_enabled: false }),
  user('Liam Novak', 'acme-logistics', 'active', { last_signed_in_at: minutes(24) }),
  user('Priya Raman', 'northwind', 'active', { last_signed_in_at: minutes(58) }),
  { ...user('billing-sync', 'northwind', 'active', { otp_enabled: false, email_verified: false, last_signed_in_at: minutes(2) }), kind: 'machine', email: '' },
]

// ── Applications and OAuth clients ──
const app = (name, uris) => ({ id: uuid(`app-${name}`), name, redirect_uris: uris, active: true })
export const applications = [
  app('Northwind Web', ['https://app.northwind.example/callback']),
  app('Northwind Mobile', ['northwind://callback', 'http://127.0.0.1:8123/cb']),
  app('Partner Portal', ['https://partners.northwind.example/auth/callback']),
  app('Billing Worker', []),
]
const client = (key, application, resource, extra = {}) => ({
  id: uuid(`client-${key}`), application_id: application.id, application_name: application.name, resource_id: resource.id, resource_name: resource.name,
  redirect_uris: application.redirect_uris, public: true, hosted_login: true, active: true, access_token_format: 'jwt', grant_types: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_method: 'none', post_logout_redirect_uris: [], allowed_origins: [], warnings: null, ...extra,
})
export const oauthClients = [
  client('web', applications[0], billing, { public: false, token_endpoint_auth_method: 'private_key_jwt', token_endpoint_auth_signing_alg: 'RS256', post_logout_redirect_uris: ['https://app.northwind.example/'], allowed_origins: ['https://app.northwind.example'], grant_types: ['authorization_code', 'refresh_token'] }),
  client('mobile', applications[1], projectsApi, { warnings: [{ code: 'loopback_redirect', field: 'redirect_uris', value: 'http://127.0.0.1:8123/cb' }] }),
  client('partners', applications[2], billing, { public: false, token_endpoint_auth_method: 'client_secret_basic', access_token_format: 'opaque', backchannel_logout_uri: 'https://partners.northwind.example/logout' }),
]

// ── Sessions ──
const session = (n, who, org, app, ago, extra = {}) => ({
  id: uuid(`session-${n}`), user_id: who.id, user_name: who.name, user_email: who.email, organization_id: org.id, organization_name: org.name,
  application_id: app.id, application_name: app.name, resource_id: billing.id, resource_name: billing.name,
  authenticated_at: minutes(ago), expires_at: minutes(ago - 600), revoked_at: null, ...extra,
})
const sessionRows = [
  session(1, users[0], acme, applications[0], 1), session(2, users[4], cobalt, applications[0], 12), session(3, users[1], acme, applications[1], 34),
  session(4, users[3], brightside, applications[2], 41, { revoked_at: minutes(30) }),
  session(5, users[2], acme, applications[0], 55, { impersonated: true, impersonator: 'priya@northwind.example', impersonation_reason: 'Ticket 4821: missing invoices' }),
  session(6, users[6], acme, applications[2], 90),
]

// ── Service accounts, SCIM tokens ──
const serviceAccount = (key, name, application, extra = {}) => ({
  id: uuid(`sa-${key}`), name, application_id: application.id, application_name: application.name, resource_id: billing.id, resource_name: billing.name,
  permissions: ['billing:read', 'billing:export'], expires_at: days(-180), revoked_at: null, token_endpoint_auth_method: 'client_secret_basic', ...extra,
})
const serviceAccounts = [
  serviceAccount('sync', 'billing-sync', applications[3]),
  serviceAccount('reports', 'nightly-reports', applications[3], { permissions: ['billing:read'], token_endpoint_auth_method: 'private_key_jwt', expires_at: days(-90) }),
  serviceAccount('support', 'support-console', applications[0], { permissions: ['billing:read', 'billing:refund'], can_impersonate: true, expires_at: days(-30) }),
]
const scim = [
  ['okta', 'Okta · Acme', acme, 'acme-okta', 'verified_domains'], ['entra', 'Entra ID · Brightside', brightside, 'brightside-entra', 'any'], ['ad', 'Azure AD · Cobalt', cobalt, 'cobalt-ldap', 'verified_domains'],
].map(([key, name, org, conn, scope], n) => ({
  id: uuid(`scim-${key}`), name, organization_id: org.id, organization_name: org.name, connection_id: uuid(`conn-${conn}`), connection_name: name,
  expires_at: days(-(300 - n * 60)), revoked_at: null, adopt_existing_members: true, adopt_scope: scope,
}))

// ── Policies ──
const password = { min_length: 14, require_upper: true, require_lower: true, require_digit: true, require_symbol: false, max_age_days: 90, lockout_threshold: 5, lockout_minutes: 15, breach_check: true, custom: true, updated_at: minutes(130) }
const signIn = { allow_password: true, allow_email_code: true, allow_social: true, allow_passkey: true, allow_password_reset: true, mfa_required: true, mfa_for_federated: false, allow_signup: false, require_terms: false, signup_organization_id: '', signup_group_id: '', allowed_factors: ['totp', 'webauthn'], custom: true, updated_at: minutes(300) }

// ── Keys, webhooks, usage ──
const keys = [
  { kid: 'k-2026-10', environment_id: ENV, alg: 'RS256', state: 'active', created_at: days(40), activated_at: days(40) },
  { kid: 'k-2026-07', environment_id: ENV, alg: 'RS256', state: 'retiring', created_at: days(120), activated_at: days(120), retire_after: minutes(-60 * 24 * 6) },
  { kid: 'k-2026-04', environment_id: ENV, alg: 'RS256', state: 'retired', created_at: days(210), activated_at: days(210), retired_at: days(40) },
]
const hook = (key, name, url, types, extra = {}) => ({ id: uuid(`hook-${key}`), name, url, types, active: true, pending: 0, created_at: days(60), updated_at: days(2), ...extra })
const webhooks = [
  hook('crm', 'CRM sync', 'https://hooks.northwind.example/crm', ['user.created', 'user.updated']),
  hook('siem', 'SIEM export', 'https://siem.northwind.example/ingest', ['session.*', 'login.failed']),
  hook('billing', 'Billing alerts', 'https://hooks.northwind.example/billing', ['role.*'], { failing_since: minutes(40), pending: 3 }),
]
const usageDays = Array.from({ length: 30 }, (_, n) => {
  const w = 1 + .25 * Math.sin(n / 2.2) + n / 90
  return { day: new Date(Date.parse('2026-09-08T00:00:00Z') + n * 86_400_000).toISOString().slice(0, 10), metrics: { logins: Math.round(2100 * w), users_created: Math.round(38 * w), tokens: Math.round(6400 * w), emails: Math.round(260 * w), sms: 0, action_calls: Math.round(900 * w), api_requests: Math.round(41000 * w) } }
})
const sum = k => usageDays.reduce((a, d) => a + d.metrics[k], 0)
const usage = {
  days: usageDays,
  totals: Object.fromEntries(['logins', 'users_created', 'tokens', 'emails', 'sms', 'action_calls', 'api_requests'].map(k => [k, sum(k)])),
  now: [{ name: 'users_max', count: 12480, max: 25000 }, { name: 'organizations_max', count: 38, max: 100 }, { name: 'applications_max', count: 7, max: null }],
}
const limits = { deployment: { users_max: 50000 }, environment: { users_max: 25000, organizations_max: 100 }, effective: { users_max: 25000, organizations_max: 100 }, updated_at: days(14) }

const features = [
  { name: 'beta_languages', description: 'Offer beta languages on hosted pages', scope: 'environment', default: true, deployment: null, environment: null, enabled: true },
  { name: 'saml_idp', description: 'Serve SAML as an identity provider', scope: 'deployment', default: true, deployment: true, environment: null, enabled: true },
]

// ── Organization (Acme) pages ──
const members = users.filter(u => u.email.includes('acme')).map(u => ({ user_id: u.id, user_name: u.name, user_email: u.email, active: true, manager_id: null, manager_name: null }))
const domains = [
  { id: uuid('dom-1'), organization_id: acme.id, domain: 'acme-logistics.example', verified: true, verified_at: days(80), verified_by: uuid('operator'), verification_method: 'dns', created_at: days(81), verification: { type: 'TXT', name: '_iamkit.acme-logistics.example', value: 'iamkit-verify=9f3a' } },
  { id: uuid('dom-2'), organization_id: acme.id, domain: 'acme.example', verified: false, verified_at: null, verified_by: null, verification_method: null, created_at: days(1), verification: { type: 'TXT', name: '_iamkit.acme.example', value: 'iamkit-verify=77c1' } },
]
const groups = [['Finance', 'Billing and invoices', 14], ['Operations', 'Fleet dispatchers', 52], ['Support', 'Tier 1 and 2', 9]].map(([name, description, count], n) => ({ id: uuid(`group-${name}`), name, description, connection_id: n === 1 ? uuid('conn-acme-okta') : null, member_count: count, created_at: days(70), updated_at: days(3) }))
const invitations = [
  ['elena@acme-logistics.example', 'pending', 2], ['raj@acme-logistics.example', 'pending', 5], ['nora@acme-logistics.example', 'accepted', 9],
].map(([email, status, ago], n) => ({ id: uuid(`inv-${n}`), organization_id: acme.id, email, role_ids: [], group_ids: [], inviter: 'priya@northwind.example', expires_at: days(-5), accepted_at: status === 'accepted' ? days(ago - 1) : null, revoked_at: null, created_at: days(ago), status }))

const roleAssignments = [[users[0], 'Billing analyst'], [users[1], 'Billing analyst'], [users[2], 'Projects editor'], [users[6], 'Organization viewer'], [users[0], 'Organization owner']].map(([u, role]) => ({
  organization_id: acme.id, organization_name: acme.name, user_id: u.id, user_name: u.name, user_email: u.email,
  resource_id: role.startsWith('Org') ? resources[2].id : (role === 'Projects editor' ? projectsApi.id : billing.id), resource_name: role.startsWith('Org') ? 'IAM' : (role === 'Projects editor' ? projectsApi.name : billing.name),
  role_id: uuid(role === 'Billing analyst' ? 'role-analyst' : role === 'Projects editor' ? 'role-projects-editor' : role === 'Organization viewer' ? 'role-org_viewer' : 'role-org_owner'), role_name: role,
}))

const brand = (name, primary, mode, extra = {}) => ({
  display_name: name, logo_url: '', accent_color: primary,
  theme: { mode, radius: 12, spacing: 'normal', align: 'center', light: { primary, background: '#f5f5f7', card: '#ffffff', text: '#1d1d1f', header: '' }, dark: { primary, background: '#0f1115', card: '#1a1d23', text: '#f2f2f3', header: '' }, logo_dark_url: '', favicon_url: '', logo_position: 'card', header: { show: false }, footer: { text: '', links: [] }, background_image_url: '', background_overlay: 0, font: { family: 'inter' }, heading_font: { family: 'inter' } },
  updated_at: days(9), ...extra,
})

// ── Activity: semantic events (filterable) and the operator change log ──
const eventRows = [
  ['session.created', 'Maya Chen', 1], ['login.failed', 'Tomás Berg', 2], ['login.failed', 'Tomás Berg', 3], ['login.failed', 'Tomás Berg', 3], ['role.created', 'Priya Raman', 6],
  ['membership.created', 'Priya Raman', 7], ['user.provisioned', 'Hannah Weiss', 12], ['mfa.enrolled', 'Omar Haddad', 18], ['federation.jit', 'Liam Novak', 24],
  ['session.created', 'Sofia Alvarez', 31], ['login.failed', 'unknown@mailinator.example', 44], ['signing_key.activate', 'Priya Raman', 58], ['session.created', 'Daniel Okafor', 63],
].map(([type, who, ago], n) => ({
  id: 900 - n, type, occurred_at: minutes(ago),
  actor: { kind: ['role.created', 'membership.created', 'signing_key.activate'].includes(type) ? 'user' : type === 'user.provisioned' ? 'directory' : 'user', id: uuid(`user-${who}`) },
  subject: { kind: type.split('.')[0], id: uuid(`subject-${n}`) },
}))
const changeLog = [
  ['password_policy.update', 'Priya Raman', 'Password policy', 130], ['signing_key.activate', 'Priya Raman', 'k-2026-10', 58], ['webhook.create', 'Priya Raman', 'SIEM export', 75],
  ['sign_in_policy.update', 'Priya Raman', 'Sign-in methods', 300], ['role_assignment.create', 'Priya Raman', 'Billing analyst · Maya Chen', 410], ['provisioning_credential.create', 'Priya Raman', 'Okta · Acme', 900],
].map(([action, who, target, ago], n) => ({ id: uuid(`chg-${n}`), actor_id: uuid('operator'), actor_label: who, action, target_id: uuid(`chg-t-${n}`), target_label: target, created_at: minutes(ago) }))
const deliveries = [
  [1, 'session.created', 'delivered', 204, 1], [2, 'login.failed', 'delivered', 204, 3], [3, 'login.failed', 'delivered', 204, 3], [4, 'session.created', 'delivered', 204, 31],
].map(([id, event_type, status, response_status, ago]) => ({ id, event_id: 800 + id, event_type, status, attempts: 1, response_status, queued_at: minutes(ago), finished_at: minutes(ago) }))
const failing = [[11, 'role.created', 6], [12, 'role.created', 7], [13, 'role.updated', 40]].map(([id, event_type, ago]) => ({ id, event_id: 700 + id, event_type, status: 'failed', attempts: 9, response_status: 503, last_error: 'endpoint answered 503', queued_at: minutes(ago) }))

/** Stateful console for the takes: roles (consoleSim) plus what a take clicks. */
export function liveSim() {
  const base = consoleSim()
  const revoked = new Set(), unlocked = new Set(), domainsVerified = new Set(), suspended = new Set()
  let keyList = keys.map(k => ({ ...k })), made = 0
  return async (method, p, url, request) => {
    const first = await base(method, p, url, request)
    if (first !== undefined) return first
    let m
    if (method === 'GET' && p === `${BASE}/sessions`) {
      const only = url.searchParams.get('user_id')
      return list(sessionRows.filter(s => !only || s.user_id === only).map(s => revoked.has(s.id) ? { ...s, revoked_at: minutes(0) } : s), 1206)
    }
    if (method === 'DELETE' && (m = p.match(/\/sessions\/(.+)$/))) { revoked.add(m[1]); return {} }
    if (method === 'POST' && (m = p.match(/\/users\/([^/]+)\/deactivate$/))) { suspended.add(m[1]); revoked.add(...sessionRows.filter(r => r.user_id === m[1]).map(r => r.id)); return {} }
    if (method === 'GET' && (m = p.match(/\/users\/([^/]+)$/)) && suspended.has(m[1])) return { ...users.find(u => u.id === m[1]), active: false, state: 'suspended' }
    if (method === 'GET' && (m = p.match(/\/users\/([^/]+)$/)) && unlocked.has(m[1])) return { ...users.find(u => u.id === m[1]), state: 'active', locked_until: null, failed_logins: 0 }
    if (method === 'POST' && (m = p.match(/\/users\/([^/]+)\/unlock$/))) { unlocked.add(m[1]); return {} }
    if (method === 'GET' && p === `${BASE}/users`) return list(search(users, url).map(u => suspended.has(u.id) ? { ...u, active: false, state: 'suspended' } : unlocked.has(u.id) ? { ...u, state: 'active' } : u), 12480)
    if (method === 'GET' && p === `${BASE}/signing-keys`) return list(keyList)
    if (method === 'POST' && p === `${BASE}/signing-keys`) { made++; const k = { kid: 'k-2026-11', environment_id: ENV, alg: 'RS256', state: 'next', created_at: minutes(0) }; keyList = [k, ...keyList]; return k }
    if (method === 'POST' && (m = p.match(/\/signing-keys\/(.+)\/activate$/))) { keyList = keyList.map(k => k.kid === m[1] ? { ...k, state: 'active', activated_at: minutes(0) } : k.state === 'active' ? { ...k, state: 'retiring', retire_after: minutes(-60 * 24 * 7) } : k); return {} }
    if (method === 'GET' && p === `${BASE}/events`) {
      const t = (url.searchParams.get('type') ?? '').trim()
      const hit = e => !t || t.split(',').some(x => (x = x.trim()).endsWith('*') ? e.type.startsWith(x.slice(0, -1)) : e.type === x)
      return { items: eventRows.filter(hit), next: 0 }
    }
    if (method === 'POST' && p === `${BASE}/webhooks/${uuid('hook-siem')}/test`) return { delivered: true, status: 204 }
    if (method === 'POST' && p === `${BASE}/webhooks/${uuid('hook-billing')}/test`) return { delivered: false, status: 503, error: 'endpoint answered 503' }
    if (method === 'GET' && (m = p.match(/\/webhooks\/([^/]+)\/deliveries$/))) { const rows = m[1] === uuid('hook-billing') ? failing : deliveries; const st = url.searchParams.get('status'); return list(st ? rows.filter(r => r.status === st) : rows) }
    if (method === 'GET' && (m = p.match(/\/webhooks\/([^/]+)$/)) && webhooks.find(w => w.id === m[1])) return webhooks.find(w => w.id === m[1])
    if (method === 'POST' && (m = p.match(/\/domains\/([^/]+)\/verify$/))) { domainsVerified.add(m[1]); return { ...domains.find(d => d.id === m[1]), verified: true, verified_at: minutes(0), verification_method: 'dns' } }
    if (method === 'GET' && p === `${BASE}/organizations/${acme.id}/domains`) return list(domains.map(d => domainsVerified.has(d.id) ? { ...d, verified: true, verified_at: minutes(0), verification_method: 'dns' } : d))
  }
}

export const extra = {
  [`${BASE}/federation-connections`]: url => url.searchParams.get('organization_id') ? list(sso.filter(c => c.organization_id === url.searchParams.get('organization_id'))) : url.searchParams.get('scope') === 'organization' ? list(sso) : list(social),
  [`${BASE}/users`]: url => list(search(users, url), 12480),
  [`${BASE}/applications`]: url => list(search(applications, url), 7),
  [`${BASE}/oauth-clients`]: url => list(search(oauthClients, url, ['application_name']), 11),
  [`${BASE}/audit-events`]: list(changeLog, 128),
  [`${BASE}/events`]: { items: eventRows, next: 0 },
  [`${BASE}/sessions`]: url => list(sessionRows.filter(s => !url.searchParams.get('user_id') || s.user_id === url.searchParams.get('user_id')), 1206),
  [`${BASE}/service-accounts`]: list(serviceAccounts),
  [`${BASE}/provisioning-credentials`]: list(scim),
  [`${BASE}/password-policy`]: password,
  [`${BASE}/sign-in-policy`]: signIn,
  [`${BASE}/signing-keys`]: list(keys),
  [`${BASE}/webhooks`]: list(webhooks),
  [`${BASE}/usage`]: usage,
  [`${BASE}/limits`]: limits,
  [`${BASE}/features`]: { items: features },
  [`${BASE}/role-assignments`]: list(roleAssignments),
  [`${BASE}/groups`]: list([]),
  [`${BASE}/login-settings`]: brand('Northwind', '#e8542f', 'dark'),
  [`${BASE}/login-settings/clients`]: list([brand('Lumen Health', '#0e9f8e', 'light', { client_id: oauthClients[1].id })]),
  [`${BASE}/login-settings/sign-in`]: list([]),
  [`${BASE}/login-settings/preview`]: { html: '' },
  [`${BASE}/organizations/${acme.id}`]: { id: acme.id, name: acme.name, active: true, mfa_required: true, mfa_for_federated: false, allow_password: true, allow_email_code: true, allow_social: false, allow_passkey: true, allowed_factors: ['totp', 'webauthn'] },
  [`${BASE}/organizations/${acme.id}/domains`]: list(domains),
  [`${BASE}/organizations/${acme.id}/groups`]: list(groups),
  [`${BASE}/organizations/${acme.id}/invitations`]: list(invitations),
  [`${BASE}/organizations/${acme.id}/password-policy`]: { ...password, custom: false, min_length: 0 },
  ...Object.fromEntries(users.map(u => [`${BASE}/users/${u.id}`, u])),
  ...Object.fromEntries(users.map(u => [`${BASE}/users/${u.id}/factors`, { factors: u.otp_enabled ? [{ id: uuid(`f-${u.id}`), kind: 'totp', confirmed_at: days(30), last_used_at: minutes(60), created_at: days(30) }, { id: uuid(`w-${u.id}`), kind: 'webauthn', passkey: true, name: 'MacBook Touch ID', confirmed_at: days(20), last_used_at: minutes(300), created_at: days(20) }] : [], recovery_codes_remaining: 8 }])),
  ...Object.fromEntries(applications.map(a => [`${BASE}/applications/${a.id}`, a])),
  ...Object.fromEntries(applications.map(a => [`${BASE}/applications/${a.id}/resources`, list([billing, projectsApi])])),
  ...Object.fromEntries(oauthClients.map(c => [`${BASE}/oauth-clients/${c.id}`, c])),
  ...Object.fromEntries(oauthClients.map(c => [`${BASE}/login-settings/clients/${c.id}/sign-in`, { client_id: c.id, password: true, email_code: true, organization_sso: true, all_connections: true, connection_ids: [], signup: false, passkey: true, custom: false }])),
}
// Paginated sub-lists that depend on a path argument.
export const members_of_acme = { [`${BASE}/organizations/${acme.id}/members`]: url => list(search(members, url, ['user_name', 'user_email'])) }
export { acme, brightside, cobalt, hook, webhooks }
