// Fictional data for the launch video: a made-up company ("Northwind Cloud")
// and its customers. Nothing here comes from a real deployment.
import { createHash } from 'node:crypto'

/** Stable UUID-shaped ids, so the console shows realistic short ids. */
export const uuid = seed => {
  const h = createHash('sha1').update(seed).digest('hex')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`
}

export const PROJECT = uuid('project')
export const ENV = uuid('env-production')
export const ENV_STAGING = uuid('env-staging')
const BASE = `/environments/${ENV}`
const list = (items, total = items.length) => ({ items, page: { total } })

const minutes = n => new Date(Date.parse('2026-10-07T17:00:00Z') - n * 60_000).toISOString()

// ── Resources (APIs) ──
const resource = (key, name, prefix, audience, permissions, extra = {}) =>
  ({ id: uuid(`resource-${key}`), name, prefix, audience, permissions, active: true, ...extra })
export const resources = [
  resource('billing', 'Billing API', 'billing', 'https://api.northwind.example/billing', ['billing:read', 'billing:write', 'billing:refund', 'billing:export']),
  resource('projects', 'Projects API', 'projects', 'https://api.northwind.example/projects', ['projects:read', 'projects:write', 'projects:delete']),
  resource('iam', 'IAM', 'iam', 'urn:iamkit:environment:production', ['iam:org:users:read', 'iam:org:users:write', 'iam:org:roles:write', 'iam:org:audit:read'], { system: true }),
]
const billing = resources[0], projectsApi = resources[1], iam = resources[2]

// ── Organizations and people ──
export const organizations = [
  ['Acme Logistics', true], ['Brightside Health', true], ['Cobalt Energy', true], ['Dunmore Labs', true], ['Evergreen Retail', true],
].map(([name, active]) => ({ id: uuid(`org-${name}`), name, active }))
const acme = organizations[0]

const person = (name, org, slug) => ({ id: uuid(`user-${name}`), user_id: uuid(`user-${name}`), name, user_name: name, email: `${name.split(' ')[0].toLowerCase()}@${slug}.example`, user_email: `${name.split(' ')[0].toLowerCase()}@${slug}.example`, active: true, organization_id: org.id })
const membersOf = {
  [acme.id]: [person('Maya Chen', acme, 'acme-logistics'), person('Daniel Okafor', acme, 'acme-logistics'), person('Sofia Alvarez', acme, 'acme-logistics'), person('Liam Novak', acme, 'acme-logistics')],
}

// ── Roles ──
const role = (key, name, res, permissions, extra = {}) =>
  ({ id: uuid(`role-${key}`), name, resource_id: res.id, resource_name: res.name, permissions, ...extra })
const builtIn = (key, name, permissions) => role(key, name, iam, permissions, { system_role: key })
const roles0 = [
  role('analyst', 'Billing analyst', billing, ['billing:read', 'billing:export']),
  role('projects-editor', 'Projects editor', projectsApi, ['projects:read', 'projects:write']),
  builtIn('org_owner', 'Organization owner', ['iam:org:users:read', 'iam:org:users:write', 'iam:org:roles:write', 'iam:org:audit:read']),
  builtIn('org_viewer', 'Organization viewer', ['iam:org:users:read', 'iam:org:audit:read']),
  builtIn('org_user_manager', 'User manager', ['iam:org:users:read', 'iam:org:users:write']),
  builtIn('org_resource_manager', 'Resource manager', ['iam:org:roles:write']),
]

// ── Audit trail shown on the environment home ──
const audit = [
  ['mfa.enrolled', 3], ['federation.jit', 9], ['signing_key.create', 26], ['invitation.create', 41], ['webhook.create', 75], ['password_policy.update', 130],
].map(([action, ago], n) => ({ id: uuid(`audit-${n}`), action, actor_id: uuid('operator'), target_id: uuid(`target-${n}`), created_at: minutes(ago) }))

// ── Semantic event log (Activity) ──
const person2 = n => ({ kind: 'user', id: uuid(`user-${n}`) })
const events = [
  ['session.created', 'user', 'Maya Chen', 1], ['login.failed', 'user', 'Tomás Berg', 3], ['role.created', 'operator', 'Priya Raman', 6],
  ['membership.created', 'operator', 'Priya Raman', 7], ['user.provisioned', 'directory', 'Hannah Weiss', 12], ['mfa.enrolled', 'user', 'Omar Haddad', 18],
  ['federation.jit', 'user', 'Liam Novak', 24], ['session.created', 'user', 'Sofia Alvarez', 31], ['signing_key.activate', 'operator', 'Priya Raman', 58],
].map(([type, kind, who, ago], n) => ({
  id: 900 - n, type, occurred_at: minutes(ago),
  actor: kind === 'user' ? person2(who) : { kind: kind === 'directory' ? 'directory' : 'user', id: uuid(`op-${who}`) },
  subject: { kind: type.split('.')[0], id: uuid(`subject-${n}`) },
}))

// ── Federation ──
const connection = (key, name, provider, extra) =>
  ({ id: uuid(`conn-${key}`), organization_id: null, organization_name: '', name, provider, issuer: '', client_id: 'c', active: true, linked: 0, jit_provisioning: true, enforcement: 'optional', signup: true, link_email: true, ...extra })
export const social = [
  connection('google', 'Google', 'google', { linked: 4120 }),
  connection('microsoft', 'Microsoft', 'microsoft', { linked: 2893 }),
  connection('github', 'GitHub', 'github', { linked: 1764 }),
]
export const sso = [
  connection('acme-okta', 'Acme Okta', 'saml', { organization_id: acme.id, organization_name: 'Acme Logistics', linked: 612 }),
  connection('brightside-entra', 'Brightside Entra ID', 'oidc', { organization_id: organizations[1].id, organization_name: 'Brightside Health', issuer: 'https://login.example/brightside/v2.0', linked: 438 }),
  connection('cobalt-ldap', 'Cobalt Active Directory', 'ldap', { organization_id: organizations[2].id, organization_name: 'Cobalt Energy', linked: 205 }),
]

const counts = { users: 12480, organizations: 38, applications: 7, resources: 3, 'oauth-clients': 11, sessions: 1206 }

const search = (items, url, keys = ['name', 'email']) => {
  const q = (url.searchParams.get('search') ?? '').toLowerCase()
  return q ? items.filter(i => keys.some(k => String(i[k] ?? '').toLowerCase().includes(q))) : items
}

/** Stateful API: roles can be created and assigned during a take. */
export function consoleSim() {
  const roles = [...roles0]
  return async (method, p, url, request) => {
    if (method === 'GET' && p === `${BASE}/roles`) return list(search(roles, url), roles.length)
    if (method === 'POST' && p === `${BASE}/roles`) {
      const body = request.postDataJSON()
      const res = resources.find(r => r.id === body.resource_id)
      const created = { id: uuid(`role-${body.name}`), name: body.name, resource_id: res.id, resource_name: res.name, permissions: body.permissions }
      roles.unshift(created)
      return created
    }
    if (method === 'POST' && p === `${BASE}/role-assignments`) return { id: uuid('assignment') }
  }
}

/** Fixed answers (GET only unless a sim handles the call first). */
export const api = {
  '/me': { operator_id: uuid('operator'), workspace_id: uuid('workspace'), role: 'owner', method: 'password', authenticated_at: minutes(40) },
  '/login-options': { password: true, password_mode: 'password', providers: [] },
  '/preferences': { locale: 'en' },
  '/projects': list([{ id: PROJECT, name: 'Northwind Cloud' }]),
  [`/projects/${PROJECT}/environments`]: list([{ id: ENV, name: 'Production' }, { id: ENV_STAGING, name: 'Staging' }]),
  [`${BASE}/organizations`]: url => list(search(organizations, url), counts.organizations),
  [`${BASE}/resources`]: url => list(search(resources, url)),
  [`${BASE}/audit-events`]: list(audit, 128),
  [`${BASE}/events`]: { items: events, next: 0 },
  [`${BASE}/effective-roles`]: list([]),
  [`${BASE}/group-role-assignments`]: list([]),
  [`${BASE}/federation-connections`]: url => url.searchParams.get('scope') === 'organization' ? list(sso) : list(social),
  ...Object.fromEntries(resources.map(r => [`${BASE}/resources/${r.id}`, r])),
  ...Object.fromEntries(Object.entries(membersOf).map(([org, members]) => [`${BASE}/organizations/${org}/members`, url => list(search(members, url, ['name', 'email']))])),
  ...Object.fromEntries(Object.entries(counts).filter(([k]) => !['organizations', 'resources'].includes(k)).map(([k, v]) => [`${BASE}/${k}`, list([], v)])),
}
