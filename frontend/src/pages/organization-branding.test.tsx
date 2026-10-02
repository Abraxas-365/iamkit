// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { emptyBranding } from '../lib/branding'
import { toDraft, toOverrides } from './organization-branding'

const fetchMock = vi.fn()
let role = 'owner'
let overrides: Record<string, unknown> = { organization_id: 'org1', display_name: null, logo_url: null, accent_color: null, theme: null }
const env = '/environments/env1/login-settings'
const org = '/environments/env1/organizations/org1'

beforeEach(() => {
  role = 'owner'
  overrides = { organization_id: 'org1', display_name: null, logo_url: null, accent_color: null, theme: null }
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'PUT' && path === `${env}/organizations/org1`) return Response.json({ ...JSON.parse(String(init.body)), organization_id: 'org1' })
    if (init.method === 'DELETE') return new Response(null, { status: 204 })
    if (init.method === 'POST' && path === `${env}/preview`) return Response.json({ html: '<p>preview</p>' })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === org ? { id: 'org1', name: 'Acme' } :
            path === env ? { ...emptyBranding(), display_name: 'Platform', logo_url: 'https://cdn.example/p.png' } :
              path === `${env}/organizations/org1` ? overrides :
                path === `${env}/preview` ? { html: '<p>saved</p>' } :
                  path === `${env}/locales` ? { items: [] } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/organizations/org1/branding']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('converts overrides: empty inherits, the theme is whole or inherited', () => {
  const base = { ...emptyBranding(), display_name: 'Platform' }
  const { draft, own } = toDraft({ display_name: 'Acme', logo_url: null, accent_color: '#aa0000', theme: null }, base)
  expect(own).toBe(false)
  expect(draft.display_name).toBe('Acme')
  expect(draft.logo_url).toBe('')
  expect(toOverrides(draft, false)).toEqual({ display_name: 'Acme', logo_url: null, accent_color: '#aa0000', theme: null, locale: null })
  expect(toOverrides({ ...draft, locale: 'es' }, false).locale).toBe('es')
  expect(toDraft({ display_name: null, logo_url: null, accent_color: null, theme: null, locale: 'es' }, base).draft.locale).toBe('es')
  const themed = toOverrides({ ...draft, theme: { ...draft.theme, light: { ...draft.theme.light, primary: '#00aa00' } } }, true)
  expect(themed.accent_color).toBe('#00aa00')
  expect(themed.theme?.light.primary).toBe('#00aa00')
})

it('shows inherited values and saves only what the organization sets', async () => {
  open()
  const name = await screen.findByLabelText('Display name')
  expect(name.getAttribute('placeholder')).toBe('Inherited: Platform')
  expect(screen.getByLabelText('Logo URL').getAttribute('placeholder')).toBe('Inherited: https://cdn.example/p.png')
  await userEvent.type(name, 'Acme Corp')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].body).toEqual({ display_name: 'Acme Corp', logo_url: null, accent_color: null, theme: null, locale: null })
  // The live preview sends the overrides as a draft organization.
  await waitFor(() => expect(calls('POST').filter(c => c.url.includes('/preview')).at(-1)?.body.organization?.display_name).toBe('Acme Corp'))
})

it('removes saved overrides', async () => {
  overrides = { ...overrides, display_name: 'Acme Corp' }
  open()
  await userEvent.click(await screen.findByRole('button', { name: /Remove organization branding/ }))
  await userEvent.click(screen.getByRole('button', { name: 'Remove' }))
  await waitFor(() => expect(calls('DELETE')).toHaveLength(1))
  expect(calls('DELETE')[0].url).toContain(`${env}/organizations/org1`)
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  overrides = { ...overrides, display_name: 'Acme Corp' }
  open()
  const name = await screen.findByLabelText('Display name')
  expect(name.matches(':disabled')).toBe(true)
  expect(screen.queryByRole('button', { name: /Remove organization branding/ })).toBeNull()
  // Viewers see the saved overrides rendered by the server.
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).includes('/login-settings/preview?') && String(url).includes('organization=org1') && !init?.method)).toBe(true))
})
