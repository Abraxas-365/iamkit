// Fictional enterprise walkthrough. Real console components; no external IdP calls.
import { ENV, PROJECT, uuid, resources, sso, social } from './demo-data.mjs'
import { liveSim, extra, applications, oauthClients, acme, users } from './demo-extra.mjs'
import { envUrl } from './harness.mjs'
const B = `/environments/${ENV}`
const list = items => ({ items, page: { total: items.length } })
const finance = uuid('group-Finance')
export function enterpriseSim() {
  const fallback = liveSim(), apps = structuredClone(applications), clients = structuredClone(oauthClients)
  const bindings = []
  let policy = { ...extra[`${B}/sign-in-policy`], allow_signup: true, require_terms: true, signup_organization_id: acme.id, signup_group_id: finance }
  return async (method, p, url, req) => {
    const body = () => req.postDataJSON()
    if (p === `${B}/action-targets`) return list([{ id: uuid('risk-action'), name: 'Corporate risk check', url: 'https://risk.northwind.example/sign-in', kind: 'call', timeout_ms: 2000, interrupt_on_error: true }])
    if (p === `${B}/action-conditions`) return list([{ name: 'function:pre_sign_in', description: 'Evaluate corporate access policy before sign-in', deny: true, claims: false }])
    if (p === `${B}/action-executions`) return list([{ condition: 'function:pre_sign_in', targets: [uuid('risk-action')] }])
    if (p === `${B}/saml/identity-provider`) return { entity_id: 'https://identity.northwind.example/saml', sso_url: 'https://identity.northwind.example/saml/sso', metadata_url: 'https://identity.northwind.example/saml/metadata', certificate: 'Demo certificate — configure your deployment signing key' }
    if (p === `${B}/saml/service-providers`) return list([{ id: uuid('legacy-hr'), name: 'Workforce HR', application_name: 'Employee Portal', resource_name: 'HR API', entity_id: 'https://hr.northwind.example', acs_urls: ['https://hr.northwind.example/saml/acs'], name_id_format: 'email', attributes: { mail: 'email', displayName: 'name' } }])
    if (p === `${B}/applications`) {
      if (method === 'POST') { const a = { ...body(), id: uuid('enterprise-app'), active: true }; apps.push(a); return a }
      if (method === 'GET') return list(apps)
    }
    if (p === `${B}/oauth-clients`) {
      if (method === 'POST') { const c = { ...body(), id: uuid('enterprise-client'), active: true, application_name: apps.find(a => a.id === body().application_id)?.name, resource_name: resources.find(r => r.id === body().resource_id)?.name }; clients.push(c); return { ...c, client_id: c.id, client_secret: '' } }
      if (method === 'GET') return list(clients)
    }
    if (p === `${B}/sign-in-policy`) { if (method === 'PUT') policy = body(); return policy }
    if (p === `${B}/group-role-assignments`) {
      if (method === 'POST') { bindings.push({ ...body(), group_name: 'Finance', role_name: 'Billing analyst', resource_name: 'Billing API', resource_id: resources[0].id }); return {} }
      return list(bindings)
    }
    if (p === `${B}/organizations/${acme.id}/groups/${finance}`) return { id: finance, name: 'Finance', description: 'Billing and invoices', member_count: 2, connection_id: null }
    if (p === `${B}/organizations/${acme.id}/groups/${finance}/members`) return list(users.slice(0, 2).map(u => ({ user_id: u.id, user_name: u.name, user_email: u.email, active: true })))
    if (p === `${B}/federation-connections`) {
      const connections = [...sso, { ...sso[0], id: uuid('workspace-sso'), name: 'Acme Google Workspace', provider: 'google', options: { domains: ['acme-logistics.example'] } }]
      return list(url.searchParams.get('scope') === 'organization' ? connections : social)
    }
    return fallback(method, p, url, req)
  }
}
const option = (page, name) => page.locator('ul li').filter({ hasText: name }).first()
async function open(page, url, route, heading, k, title, sub) {
  await page.goto(envUrl(url, route)); await page.getByRole('heading', { name: heading, exact: true }).first().waitFor()
  await k.start(); k.cap(title, sub); await k.pause(2200)
}
export const enterpriseTakes = {
  async actions(page, url, k) {
    await open(page, url, '/actions', 'Actions', k, 'Extend identity with your own logic', 'Signed calls can deny a sign-in, add claims or adjust a request')
    await k.scrollTo(page.getByText('Corporate risk check', { exact: true }).first()); await k.pause(3500)
    await k.click(page.getByRole('button', { name: 'Add target', exact: true }))
    k.cap('Synchronous or asynchronous', 'Choose response handling, timeouts and fail-closed behavior'); await k.pause(5000)
    await k.click(page.getByRole('button', { name: 'Cancel', exact: true }))
  },
  async saml(page, url, k) {
    await open(page, url, '/saml-apps', 'SAML applications', k, 'Bring existing enterprise apps along', 'IAMKit can also be the SAML identity provider')
    await k.pause(3000)
    await k.click(page.getByRole('button', { name: 'Add SAML application', exact: true }))
    k.cap('Connect a SAML service provider', 'Entity ID, allowed assertion URLs, NameID and attributes'); await k.pause(5000)
    await k.click(page.getByRole('button', { name: 'Cancel', exact: true }))
  },
  async environments(page, url, k) {
    await page.goto(`${url}/projects/${PROJECT}`)
    await page.getByRole('heading', { name: 'Environments', exact: true }).waitFor(); await k.start()
    k.cap('Separate testing from production', 'Each environment has its own identity and access configuration')
    await k.glide(await k.at(page.getByText('Staging', { exact: true }).last()), 900); await k.pause(3000)
    await k.click(page.getByRole('button', { name: 'Create environment', exact: true }))
    k.cap('Create a space for your next release', 'Development, staging and production — not a shared user directory')
    await k.type(page.getByRole('dialog').getByLabel('Name'), 'QA acceptance'); await k.pause(3000)
    await k.click(page.getByRole('button', { name: 'Cancel', exact: true })); await k.pause(1500)
  },
  async register(page, url, k) {
    await open(page, url, '/applications', 'Applications', k, 'Register your business applications', 'Web, mobile, partner portals and background workers')
    await k.click(page.getByRole('button', { name: 'Create application', exact: true }))
    const d = page.getByRole('dialog'); await k.type(d.getByLabel('Name', { exact: true }), 'Employee Portal')
    k.cap('Give the application an identity', 'Then link its APIs and configure how people sign in')
    await k.pause(1800); await k.click(d.getByRole('button', { name: 'Create', exact: true }))
    await page.getByText('Application created', { exact: true }).waitFor(); await k.pause(2500)
  },
  async oauth(page, url, k) {
    await open(page, url, '/oauth-clients', 'OAuth clients', k, 'Connect apps with OAuth', 'An application, an API audience and an allowed callback')
    await k.click(page.getByRole('button', { name: 'Create client', exact: true }))
    const d = page.getByRole('dialog')
    await k.click(d.getByRole('combobox').nth(0)); await k.click(option(page, 'Northwind Web'))
    await k.click(d.getByRole('combobox').nth(1)); await k.click(option(page, 'Billing API'))
    await k.type(d.getByLabel('Redirect URIs', { exact: true }), 'https://employees.northwind.example/callback'); await page.keyboard.press('Enter')
    k.cap('Public clients use PKCE', 'Confidential clients keep credentials on the server'); await k.pause(3000)
    await k.click(d.getByText('Your own sign-in UI', { exact: true }))
    k.cap('Bring your own sign-in UI', 'Your app renders the forms; IAMKit completes authorization'); await k.pause(3000)
    await k.click(d.getByRole('button', { name: 'Create client', exact: true }))
    await page.getByRole('heading', { name: 'OAuth client created', exact: true }).waitFor(); await k.pause(2500)
  },
  async groupRoles(page, url, k) {
    await open(page, url, `/organizations/${acme.id}/groups/${finance}`, 'Finance', k, 'Assign access to a whole team', 'Every group member inherits its roles within the organization')
    await k.click(page.getByRole('button', { name: 'Assign role', exact: true }))
    const d = page.getByRole('dialog'); await k.click(d.getByRole('combobox')); await k.click(option(page, 'Billing analyst'))
    await k.pause(2000); await k.click(d.getByRole('button', { name: 'Assign role', exact: true }))
    await page.getByText('Billing analyst', { exact: true }).first().waitFor()
    k.cap('One assignment. Every member.', 'Maya and Daniel inherit Billing analyst — no repeated grants'); await k.pause(3500)
  },
  async signup(page, url, k) {
    await open(page, url, '/sign-in-policy', 'Sign-in methods', k, 'Choose how people sign in', 'Password, email codes, passkeys, social login and organization SSO')
    await k.pause(2500)
    await k.scrollTo(page.getByText('Self sign-up', { exact: true }))
    k.cap('Make registration part of your product', 'Email verification, terms acceptance and a default organization'); await k.pause(4000)
    await k.scrollTo(page.getByText('Default group (optional)', { exact: true }))
    k.cap('Give new accounts the right access', 'A default group connects self-registration to your role model'); await k.pause(4000)
  },
  async providers(page, url, k) {
    await open(page, url, '/federation', 'Sign-in providers', k, 'Keep the corporate identity provider', 'Social login and organization SSO are separate choices')
    await k.scrollTo(page.getByText('Acme Google Workspace', { exact: true }))
    k.cap('Entra ID or Google Workspace', 'Organization SSO with tenant or domain restrictions'); await k.pause(4500)
    await k.glide(await k.at(page.getByText('Brightside Entra ID', { exact: true }).first()), 1000); await k.pause(2500)
    k.cap('SAML, OpenID Connect and LDAP', 'Federation authenticates users; SCIM handles provisioning'); await k.pause(3500)
  },
  async directory(page, url, k) {
    await open(page, url, '/provisioning', 'SCIM provisioning', k, 'Provision users from your directory', 'Inbound SCIM: the directory creates, updates and removes identities')
    await k.click(page.getByRole('button', { name: 'Connect a directory', exact: true }))
    k.cap('Issue an organization-scoped credential', 'Paste the SCIM URL and token into the external directory'); await k.pause(4500)
    await k.click(page.getByRole('button', { name: 'Cancel', exact: true }))
    await page.goto(envUrl(url, `/organizations/${acme.id}/groups`)); await page.getByText('Operations', { exact: true }).first().waitFor()
    k.cap('Directory owns membership. You own access.', 'SCIM-managed groups receive their application roles in IAMKit'); await k.pause(4500)
  },
  async machines(page, url, k) {
    await open(page, url, '/service-accounts', 'Service accounts', k, 'Secure machine-to-machine integrations', 'Service credentials for background jobs and business systems')
    await k.pause(5000)
  },
}
