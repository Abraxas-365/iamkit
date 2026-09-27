// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let role = 'owner'
const client = { id: 'c1', application_id: 'a1', application_name: 'Web', resource_id: 'r1', resource_name: 'Billing', redirect_uris: ['https://app.example/callback'], public: true, hosted_login: false, active: true }
const env = '/environments/env1'

beforeEach(() => {
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (init.method === 'PATCH') return new Response(null, { status: 204 })
    if (init.method === 'PUT' && path === `${env}/login-settings`) {
      const body = JSON.parse(String(init.body))
      if (body.accent_color && !/^#[0-9a-fA-F]{6}$/.test(body.accent_color)) return Response.json({ error: { message: 'accent color must be #rrggbb' } }, { status: 400 })
      return Response.json({ environment_id: 'env1', ...body, accent_color: body.accent_color.toLowerCase(), updated_at: '2026-09-27T00:00:00Z' })
    }
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/login-settings` ? { environment_id: 'env1', display_name: 'Acme', logo_url: '', accent_color: '' } :
            path === `${env}/oauth-clients` ? page([client]) : page([])
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open(page: string) {
  render(<MemoryRouter initialEntries={[`/projects/project1/environments/env1/${page}`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}
function calls(method: string) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === method).map(([url, init]) => ({ url: String(url), body: init.body ? JSON.parse(init.body) : undefined }))
}

it('saves hosted login branding', async () => {
  open('hosted-login')
  const name = await screen.findByLabelText('Display name')
  expect((name as HTMLInputElement).value).toBe('Acme')
  await userEvent.clear(name)
  await userEvent.type(name, 'Acme Billing')
  await userEvent.type(screen.getByLabelText('Logo URL'), 'https://cdn.example/logo.png')
  const accent = screen.getByLabelText('Accent color')
  await userEvent.clear(accent)
  await userEvent.type(accent, '#FF6600')
  await userEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls('PUT')).toHaveLength(1))
  expect(calls('PUT')[0].body).toEqual({ display_name: 'Acme Billing', logo_url: 'https://cdn.example/logo.png', accent_color: '#FF6600' })
  await waitFor(() => expect((screen.getByLabelText('Accent color') as HTMLInputElement).value).toBe('#ff6600'))
  expect((screen.getByLabelText('Display name') as HTMLInputElement).value).toBe('Acme Billing')
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open('hosted-login')
  const name = await screen.findByLabelText('Display name')
  expect((name as HTMLInputElement).disabled).toBe(true)
  expect(screen.queryByRole('button', { name: 'Save' })).toBeNull()
})

it('toggles hosted login on an OAuth client', async () => {
  open('oauth-clients')
  await screen.findByText('Your UI')
  await userEvent.click(screen.getByRole('button', { name: 'Use hosted pages' }))
  await waitFor(() => expect(calls('PATCH')).toHaveLength(1))
  expect(calls('PATCH')[0].url).toContain(`${env}/oauth-clients/c1`)
  expect(calls('PATCH')[0].body).toEqual({ hosted_login: true })
})
