// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const env = '/environments/env1'
type Feature = { name: string; description: string; scope: string; default: boolean; deployment: boolean | null; environment: boolean | null; enabled: boolean; updated_at?: string }
let features: Feature[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

beforeEach(() => {
  features = [
    { name: 'beta_languages', description: 'Offer beta languages', scope: 'environment', default: true, deployment: null, environment: null, enabled: true },
    { name: 'saml_idp', description: 'Serve SAML', scope: 'deployment', default: true, deployment: false, environment: null, enabled: false },
  ]
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    const body = init.body ? JSON.parse(String(init.body)) : undefined
    if (method !== 'GET') calls.push({ method, path, body })
    const one = path.match(/\/features\/(\w+)$/)
    if (one) {
      const i = features.findIndex(f => f.name === one[1])
      const f = features[i]
      if (method === 'PUT') features[i] = { ...f, environment: body.enabled, enabled: body.enabled, updated_at: new Date().toISOString() }
      if (method === 'DELETE') features[i] = { ...f, environment: null, enabled: f.deployment ?? f.default, updated_at: undefined }
      return Response.json(features[i])
    }
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/features` ? { items: features } :
            path.startsWith(env) ? { items: [], page: { total: 0, limit: 200, offset: 0 } } : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/features']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('overrides and resets an environment feature', async () => {
  const u = userEvent.setup()
  open()
  const toggle = await screen.findByRole('switch', { name: 'beta_languages' })
  expect(screen.getByText(/Default: on/)).toBeTruthy()
  // Deployment features are shown, never editable.
  expect(screen.getByText(/Set for the deployment \(IAMKIT_FEATURES\): off/)).toBeTruthy()
  expect(screen.queryByRole('switch', { name: 'saml_idp' })).toBeNull()

  await u.click(toggle)
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PUT', path: `${env}/features/beta_languages`, body: { enabled: false } }))
  expect(await screen.findByText(/Set for this environment/)).toBeTruthy()
  await u.click(screen.getByRole('button', { name: 'Use the default (on)' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'DELETE', path: `${env}/features/beta_languages`, body: undefined }))
  expect(await screen.findByText(/Default: on/)).toBeTruthy()
  expect((screen.getByRole('switch', { name: 'beta_languages' }) as HTMLInputElement).checked).toBe(true)
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  features[0] = { ...features[0], environment: false, enabled: false }
  open()
  const toggle = await screen.findByRole('switch', { name: 'beta_languages' }) as HTMLInputElement
  expect(toggle.disabled).toBe(true)
  expect(screen.queryByRole('button', { name: /Use the default/ })).toBeNull()
})
