// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import { restrictionError, validHostname, validIP } from '../lib/risk'
import App from '../App'

vi.setConfig({ testTimeout: 30000 }) // userEvent through the whole console is slow
const fetchMock = vi.fn()
const env = '/environments/env1'
const policyDefault = { actions: {}, thresholds: { ip_failures_per_hour: 20, ip_distinct_logins_per_hour: 10, user_failures_per_hour: 10, stale_after_days: 90, travel_speed_kmh: 900 }, notify_user: false, block_if_unverifiable: false, saved: false }
const geo = { source: 'database', database: 'city.mmdb', countries: true, travel: true }
let captcha: Record<string, unknown> | null
let policy: Record<string, unknown>
let restrictions: Record<string, unknown>[]
let status: Record<string, unknown>
let attempts: Record<string, unknown>[]
let testResult: { status: number; code?: string } | null
let putError: { status: number; code: string; message: string } | null
let role = 'owner'
let calls: { method: string; path: string; query: string; body?: Record<string, unknown> }[]

const attempt = (id: string, extra: Record<string, unknown> = {}) => ({ id, user_id: 'user-1', ip: '198.51.100.7', country: 'PE', device: true, method: 'password', surface: 'hosted', outcome: 'blocked', reason: 'detection', detections: ['ip_velocity'], action: 'block', captcha: 'passed', user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15', created_at: '2026-01-02T03:04:05Z', ...extra })

beforeEach(() => {
  captcha = null; policy = { ...policyDefault }; restrictions = []; attempts = []; testResult = null; putError = null; role = 'owner'; calls = []
  status = { geoip: geo, captcha: true, risk_signals: true }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const [path, query = ''] = url.replace('/management/v1', '').split('?')
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    if (method !== 'GET') calls.push({ method, path, query, body })
    const err = (s: number, code: string, message: string) => Response.json({ error: { code, message } }, { status: s })
    if (path === `${env}/captcha` && method === 'PUT') {
      if (putError) return err(putError.status, putError.code, putError.message)
      captcha = { environment_id: 'env1', provider: body.provider, site_key: body.site_key, has_secret: true, hosted: body.hosted, headless: body.headless, hostnames: body.hostnames, updated_at: '2026-01-01T00:00:00Z' }
      return Response.json(captcha)
    }
    if (path === `${env}/captcha` && method === 'DELETE') { captcha = null; return new Response(null, { status: 204 }) }
    if (path === `${env}/captcha/test`) return testResult && testResult.status !== 204 ? err(testResult.status, testResult.code ?? 'X', 'upstream says no') : new Response(null, { status: 204 })
    if (path === `${env}/risk-policy` && method === 'PUT') {
      if (putError) return err(putError.status, putError.code, putError.message)
      policy = { ...body, saved: true, updated_at: '2026-01-01T00:00:00Z' }; return Response.json(policy)
    }
    if (path === `${env}/risk-policy` && method === 'DELETE') { policy = { ...policyDefault }; return new Response(null, { status: 204 }) }
    if (path === `${env}/risk-restrictions` && method === 'POST') {
      if (putError) return err(putError.status, putError.code, putError.message)
      restrictions = [{ id: 'r1', note: '', created_at: '2026-01-01T00:00:00Z', ...body }]; return Response.json(restrictions[0], { status: 201 })
    }
    if (path.startsWith(`${env}/risk-restrictions/`) && method === 'DELETE') { restrictions = []; return new Response(null, { status: 204 }) }
    if (method !== 'GET') return new Response(null, { status: 204 })
    if (path === `${env}/captcha`) return captcha ? Response.json(captcha) : err(404, 'NOT_FOUND', 'no CAPTCHA is configured')
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    if (path === '/me') return Response.json({ operator_id: 'operator1', workspace_id: 'workspace1', role })
    if (path === '/projects') return Response.json([{ id: 'project1', name: 'Billing' }])
    if (path === '/projects/project1/environments') return Response.json([{ id: 'env1', name: 'Production' }])
    if (path === `${env}/risk/status`) return Response.json(status)
    if (path === `${env}/risk-policy`) return Response.json(policy)
    if (path === `${env}/risk-restrictions`) return Response.json({ items: restrictions })
    if (path === `${env}/sign-in-attempts`) {
      const before = new URLSearchParams(query).get('before')
      const rest = attempts.slice(before ? attempts.findIndex(a => a.id === before) + 1 : 0)
      const items = rest.slice(0, 2)
      return Response.json({ items, ...(rest.length > 2 && { next: items[items.length - 1].id }) })
    }
    if (path === `${env}/users/user-1`) return Response.json({ id: 'user-1', email: 'ana@example.com', name: 'Ana', active: true, state: 'active', kind: 'human', created_at: '2026-01-01T00:00:00Z' })
    if (path === `${env}/users/user-1/factors`) return Response.json({ factors: [], recovery_codes_remaining: 0 })
    if (path === `${env}/users/user-1/devices`) return Response.json({ items: [{ first_seen_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-02T00:00:00Z', last_ip: '198.51.100.9', last_country: 'PE', user_agent: 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0' }] })
    if (path.startsWith(env)) return Response.json(page([]))
    return Response.json([])
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(path: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${path}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('validates IPs, countries, domains and hostnames', () => {
  expect(validIP('203.0.113.0/24')).toBe(true)
  expect(validIP('2001:db8::/32')).toBe(true)
  expect(validIP('300.1.1.1')).toBe(false)
  expect(validIP('10.0.0.0/33')).toBe(false)
  expect(restrictionError('country', 'PE')).toBe('')
  expect(restrictionError('country', 'PER')).not.toBe('')
  expect(restrictionError('email_domain', '@example.com')).toBe('')
  expect(restrictionError('email_domain', 'localhost')).not.toBe('')
  expect(validHostname('app.example.com')).toBe(true)
  expect(validHostname('https://app.example.com')).toBe(false)
  expect(validHostname('app.example.com:8080')).toBe(false)
})

it('is in the environment navigation', async () => {
  open('security')
  expect(await screen.findByRole('heading', { name: 'Security' })).toBeTruthy()
  expect(screen.getAllByRole('link', { name: 'Security' }).length).toBeGreaterThan(0)
})

it('saves bot protection without ever showing the secret, then deletes it', async () => {
  const u = userEvent.setup()
  open('security')
  const site = await screen.findByLabelText('Site key')
  expect(screen.queryByRole('button', { name: 'Test' })).toBeNull()
  await u.click(screen.getByRole('button', { name: 'Save' }))
  expect(screen.getByText('Enter the site key, without spaces.')).toBeTruthy()
  await u.type(site, 'site-key-fake')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  expect(screen.getByText('Enter the secret key.')).toBeTruthy()
  await u.type(screen.getByLabelText('Secret key'), 'secret-fake')
  await u.type(screen.getByRole('textbox', { name: /hostnames/i }), 'App.Example.com{Enter}')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.some(c => c.method === 'PUT' && c.path === `${env}/captcha`)).toBe(true))
  const put = calls.find(c => c.method === 'PUT')!
  expect(put.body).toMatchObject({ provider: 'turnstile', site_key: 'site-key-fake', secret: 'secret-fake', hosted: true, headless: true, hostnames: ['app.example.com'] })
  expect(await screen.findByRole('button', { name: 'Test' })).toBeTruthy()
  expect(screen.getByText('Configured', { selector: 'span,div' })).toBeTruthy()
  expect((screen.getByLabelText('Secret key') as HTMLInputElement).value).toBe('')
  // saving again without a new secret does not resend it
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.filter(c => c.method === 'PUT').length).toBe(2))
  expect(calls.filter(c => c.method === 'PUT')[1].body).not.toHaveProperty('secret')
  await u.click(screen.getByRole('button', { name: 'Delete' }))
  const dialog = await screen.findByRole('alertdialog').catch(() => screen.findByRole('dialog'))
  await u.click(within(dialog).getByRole('button', { name: 'Delete' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.path === `${env}/captcha`)).toBe(true))
  expect(await screen.findByLabelText('Site key')).toBeTruthy()
})

it('rejects hostnames with a scheme or port', async () => {
  const u = userEvent.setup()
  open('security')
  await u.type(await screen.findByLabelText('Site key'), 'site-key-fake')
  await u.type(screen.getByLabelText('Secret key'), 'secret-fake')
  await u.type(screen.getByRole('textbox', { name: /hostnames/i }), 'https://app.example.com{Enter}')
  await u.click(screen.getByRole('button', { name: 'Save' }))
  expect((await screen.findAllByText(/Hostnames must be host names only/)).length).toBeGreaterThan(0)
  expect(calls.length).toBe(0)
})

it.each([
  [{ status: 204 }, 'The provider accepted the stored secret.'],
  [{ status: 422, code: 'CAPTCHA_SECRET_INVALID' }, 'The provider rejected the stored secret. Save the right secret and test again.'],
  [{ status: 502, code: 'CAPTCHA_UNREACHABLE' }, 'The CAPTCHA provider could not be reached. Try again in a moment.'],
  [{ status: 422, code: 'ENCRYPTION_KEY_REQUIRED' }, 'Secrets are stored encrypted. Set IAMKIT_ENCRYPTION_KEY on the server and restart it.'],
])('tests the stored secret: %j', async (result, text) => {
  captcha = { environment_id: 'env1', provider: 'hcaptcha', site_key: 'site-key-fake', has_secret: true, hosted: true, headless: false, hostnames: [], updated_at: '2026-01-01T00:00:00Z' }
  testResult = result
  const u = userEvent.setup()
  open('security')
  await u.click(await screen.findByRole('button', { name: 'Test' }))
  expect(await screen.findByText(text)).toBeTruthy()
  expect(calls.some(c => c.method === 'POST' && c.path === `${env}/captcha/test`)).toBe(true)
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  captcha = { environment_id: 'env1', provider: 'turnstile', site_key: 'site-key-fake', has_secret: true, hosted: true, headless: true, hostnames: [], updated_at: '2026-01-01T00:00:00Z' }
  open('security')
  const site = await screen.findByLabelText('Site key') as HTMLInputElement
  expect(site.matches(':disabled')).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Delete' })).toBeNull()
})

it('warns when the captcha feature is off', async () => {
  status = { ...status, captcha: false }
  open('security')
  expect(await screen.findByText(/feature is off for this environment/)).toBeTruthy()
})

it('shows the policy matrix with only the allowed actions and saves it', async () => {
  const u = userEvent.setup()
  open('security?tab=policy')
  const velocity = await screen.findByRole('radio', { name: 'IP address velocity: Block' })
  expect(screen.queryByRole('radio', { name: 'New device: Block' })).toBeNull() // not allowed for this detection
  expect(screen.queryByRole('radio', { name: 'IP address velocity: Notify the user' })).toBeNull()
  expect((screen.getByRole('radio', { name: 'IP address velocity: Off' }) as HTMLInputElement).checked).toBe(true)
  expect(screen.queryByText(/Log only records the detection/)).toBeNull()
  await u.click(screen.getByRole('radio', { name: 'New device: Log only' }))
  expect(screen.getByText(/Log only records the detection/)).toBeTruthy()
  await u.click(velocity)
  await u.click(screen.getByRole('switch', { name: 'Block when a challenge cannot be answered' }))
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  await waitFor(() => expect(calls.some(c => c.method === 'PUT' && c.path === `${env}/risk-policy`)).toBe(true))
  const body = calls.find(c => c.method === 'PUT')!.body as { actions: Record<string, string>; block_if_unverifiable: boolean; thresholds: Record<string, number> }
  expect(body.actions).toMatchObject({ ip_velocity: 'block', new_device: 'log', impossible_travel: 'off' })
  expect(body.block_if_unverifiable).toBe(true)
  expect(body.thresholds.stale_after_days).toBe(90)
  // the saved policy can be reset
  await u.click(await screen.findByRole('button', { name: 'Reset to default' }))
  const dialog = await screen.findByRole('alertdialog').catch(() => screen.findByRole('dialog'))
  await u.click(within(dialog).getByRole('button', { name: 'Reset' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.path === `${env}/risk-policy`)).toBe(true))
})

it('validates thresholds client-side', async () => {
  const u = userEvent.setup()
  open('security?tab=policy')
  const days = await screen.findByLabelText(/Days without signing in/)
  await u.clear(days); await u.type(days, '3')
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  expect(await screen.findByText(/must be a whole number from 7 to 3650/)).toBeTruthy()
  expect(calls.length).toBe(0)
})

it('disables impossible travel and explains why without GeoIP', async () => {
  status = { geoip: { source: 'none', countries: false, travel: false }, captcha: true, risk_signals: true }
  open('security?tab=policy')
  expect(await screen.findByText(/GeoIP is not configured on this deployment/)).toBeTruthy()
  expect((screen.getByRole('radio', { name: 'Impossible travel: Block' }) as HTMLInputElement).disabled).toBe(true)
  expect((screen.getByRole('radio', { name: 'Impossible travel: Off' }) as HTMLInputElement).disabled).toBe(false)
  expect(screen.getByText('Unavailable: this deployment has no GeoIP with coordinates.')).toBeTruthy()
})

it('explains a GEOIP_REQUIRED answer', async () => {
  putError = { status: 422, code: 'GEOIP_REQUIRED', message: 'geoip required' }
  const u = userEvent.setup()
  open('security?tab=policy')
  await u.click(await screen.findByRole('radio', { name: 'Impossible travel: Log only' }))
  await u.click(screen.getByRole('button', { name: 'Save policy' }))
  expect(await screen.findByText(/Impossible travel needs GeoIP/)).toBeTruthy()
})

it('adds, validates and removes restrictions', async () => {
  const u = userEvent.setup()
  open('security?tab=restrictions')
  expect(await screen.findByText('No restrictions')).toBeTruthy()
  const value = screen.getByLabelText('Value')
  await u.type(value, '999.1.1.1')
  await u.click(screen.getByRole('button', { name: 'Add restriction' }))
  expect(screen.getByText(/Enter an IP address or a CIDR range/)).toBeTruthy()
  expect(calls.length).toBe(0)
  await u.clear(value); await u.type(value, '203.0.113.0/24')
  await u.type(screen.getByLabelText('Note'), 'office')
  await u.click(screen.getByRole('button', { name: 'Add restriction' }))
  await waitFor(() => expect(calls.length).toBe(1))
  expect(calls[0]).toMatchObject({ method: 'POST', path: `${env}/risk-restrictions`, body: { kind: 'ip', value: '203.0.113.0/24', action: 'deny', note: 'office' } })
  expect(await screen.findByText('203.0.113.0/24')).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Actions for 203.0.113.0/24' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Remove' }))
  const dialog = await screen.findByRole('alertdialog').catch(() => screen.findByRole('dialog'))
  await u.click(within(dialog).getByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls.some(c => c.method === 'DELETE' && c.path === `${env}/risk-restrictions/r1`)).toBe(true))
})

it('disables the country kind without GeoIP', async () => {
  status = { geoip: { source: 'none', countries: false, travel: false }, captcha: true, risk_signals: true }
  open('security?tab=restrictions')
  expect(await screen.findByText(/Country rules are unavailable/)).toBeTruthy()
  expect((screen.getByRole('option', { name: 'Country' }) as HTMLOptionElement).disabled).toBe(true)
})

it('validates a country code', async () => {
  const u = userEvent.setup()
  open('security?tab=restrictions')
  await u.selectOptions(await screen.findByLabelText('Type'), 'country')
  await u.type(screen.getByLabelText('Value'), 'PER')
  await u.click(screen.getByRole('button', { name: 'Add restriction' }))
  expect(screen.getByText(/two-letter ISO country code/)).toBeTruthy()
  expect(calls.length).toBe(0)
})

it('lists sign-in attempts with filters, keyset paging and a detail drawer', async () => {
  attempts = [attempt('a3'), attempt('a2', { outcome: 'failure', detections: null, action: 'none', reason: undefined }), attempt('a1', { outcome: 'success', detections: null, action: 'none', reason: undefined })]
  const u = userEvent.setup()
  open('security?tab=attempts')
  expect((await screen.findAllByRole('button', { name: /Details of the attempt/ })).length).toBe(2)
  await u.click(screen.getByRole('button', { name: 'Load more' }))
  await waitFor(() => expect(screen.getAllByRole('button', { name: /Details of the attempt/ }).length).toBe(3))
  const queries = fetchMock.mock.calls.map(c => String(c[0])).filter(x => x.includes('sign-in-attempts'))
  expect(queries.some(q => q.includes('before=a2'))).toBe(true)
  expect(screen.queryByRole('button', { name: 'Load more' })).toBeNull()
  // filters go to the query string
  await u.selectOptions(screen.getByLabelText('Filter by outcome'), 'blocked')
  await u.selectOptions(screen.getByLabelText('Filter by detection'), 'ip_velocity')
  await u.type(screen.getByLabelText('Filter by country'), 'pe')
  await u.type(screen.getByLabelText('Filter by IP address'), '198.51.100.7')
  await u.type(screen.getByLabelText('Filter by user ID'), 'user-1')
  await waitFor(() => {
    const last = String(fetchMock.mock.calls.filter(c => String(c[0]).includes('sign-in-attempts')).at(-1)![0])
    const q = new URLSearchParams(last.split('?')[1])
    expect(Object.fromEntries(q)).toMatchObject({ outcome: 'blocked', detection: 'ip_velocity', country: 'PE', ip: '198.51.100.7', user_id: 'user-1' })
  })
  // the detail drawer
  await u.click((await screen.findAllByRole('button', { name: /Details of the attempt/ }))[0])
  const drawer = await screen.findByRole('dialog')
  expect(within(drawer).getByText('198.51.100.7')).toBeTruthy()
  expect(within(drawer).getByText('A detection with the block action fired')).toBeTruthy()
  expect(within(drawer).getByText('Passed')).toBeTruthy()
  expect(within(drawer).getByText('Hosted page')).toBeTruthy()
  expect(within(drawer).getByRole('link', { name: 'View user' }).getAttribute('href')).toBe('/projects/project1/environments/env1/users/user-1')
})

it('shows an empty state when there are no attempts', async () => {
  open('security?tab=attempts')
  expect(await screen.findByText('No sign-in attempts')).toBeTruthy()
})

it('shows recent attempts and known devices on the user page', async () => {
  attempts = [attempt('a1', { outcome: 'success', detections: null, action: 'none', reason: undefined })]
  open('users/user-1')
  expect(await screen.findByText('Recent sign-in attempts')).toBeTruthy()
  expect(await screen.findByRole('button', { name: /Details of the attempt/ })).toBeTruthy()
  expect(await screen.findByText('Known devices')).toBeTruthy()
  expect(await screen.findByText('198.51.100.9')).toBeTruthy()
  const q = fetchMock.mock.calls.map(c => String(c[0])).find(x => x.includes('sign-in-attempts'))!
  expect(new URLSearchParams(q.split('?')[1]).get('user_id')).toBe('user-1')
})
