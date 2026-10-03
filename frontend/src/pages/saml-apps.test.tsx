// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'
import { parseAttributes } from './saml-apps'

const fetchMock = vi.fn()
const env = '/environments/env1'
const wiki = { id: 'sp1', name: 'Wiki', application_id: 'app1', application_name: 'web', resource_id: 'res1', resource_name: 'Billing', entity_id: 'https://wiki.example.com/saml', acs_urls: ['https://wiki.example.com/saml/acs'], name_id_format: 'email', attributes: { mail: 'email' }, created_at: '2026-01-01T00:00:00Z' }
let providers: typeof wiki[]
let calls: { method: string; path: string; body?: Record<string, unknown> }[]
let role = 'owner'

beforeEach(() => {
  providers = [structuredClone(wiki)]
  calls = []
  role = 'owner'
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    const method = init.method ?? 'GET'
    if (method !== 'GET') calls.push({ method, path, body: init.body ? JSON.parse(String(init.body)) : undefined })
    if (path === `${env}/saml/service-providers/sp1` && method === 'PATCH') {
      providers[0] = { ...providers[0], ...JSON.parse(String(init.body)) }
      return Response.json(providers[0])
    }
    if (path === `${env}/saml/service-providers/sp1` && method === 'DELETE') {
      providers = []
      return new Response(null, { status: 204 })
    }
    const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 200, offset: 0 } })
    const data = path === '/me' ? { operator_id: 'operator1', workspace_id: 'workspace1', role } :
      path === '/projects' ? [{ id: 'project1', name: 'Billing' }] :
        path === '/projects/project1/environments' ? [{ id: 'env1', name: 'Production' }] :
          path === `${env}/saml/identity-provider` ? { entity_id: 'https://iam.example/saml/env1/metadata', metadata_url: 'https://iam.example/saml/env1/metadata', sso_url: 'https://iam.example/saml/env1/sso', certificate: '-----BEGIN CERTIFICATE-----' } :
            path === `${env}/saml/service-providers` ? page(providers) :
              path.startsWith(env) ? page([]) : []
    return Response.json(data)
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/projects/project1/environments/env1/saml-apps']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('parses name=source attributes', () => {
  expect(parseAttributes(['mail=email', ' roles = permissions '])).toEqual({ mail: 'email', roles: 'permissions' })
  expect(() => parseAttributes(['mail'])).toThrow(/name=source/)
  expect(() => parseAttributes(['mail=phone'])).toThrow(/source must be one of/)
})

it('shows the identity provider settings, edits and deletes a SAML application', async () => {
  const u = userEvent.setup()
  open()
  expect(await screen.findByText('https://wiki.example.com/saml')).toBeTruthy()
  expect(screen.getByText('web · Billing')).toBeTruthy()
  expect(await screen.findByText('https://iam.example/saml/env1/sso')).toBeTruthy()

  await u.click(screen.getByRole('button', { name: 'Actions for Wiki' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Edit' }))
  await u.click(await screen.findByRole('radio', { name: /User ID/ }))
  await u.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(calls.at(-1)).toEqual({ method: 'PATCH', path: `${env}/saml/service-providers/sp1`, body: { name: 'Wiki', acs_urls: ['https://wiki.example.com/saml/acs'], name_id_format: 'persistent', attributes: { mail: 'email' } } }))
  expect(await screen.findByText('User ID')).toBeTruthy()

  await u.click(screen.getByRole('button', { name: 'Actions for Wiki' }))
  await u.click(await screen.findByRole('menuitem', { name: 'Delete' }))
  await u.click(await screen.findByRole('button', { name: 'Delete application' }))
  expect(await screen.findByText('No SAML applications')).toBeTruthy()
})

it('explains the turned-off SAML identity provider instead of a bare error', async () => {
  const base = fetchMock.getMockImplementation()!
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => url.includes('/saml/')
    ? Response.json({ error: { message: 'Not Found', code: 'NOT_FOUND' } }, { status: 404 }) : base(url, init))
  open()
  expect(await screen.findByText('SAML identity provider turned off')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add SAML application' })).toBeNull()
  expect(screen.queryByText('Not Found')).toBeNull()
})

it('is read-only for viewers', async () => {
  role = 'viewer'
  open()
  expect(await screen.findByText('Wiki')).toBeTruthy()
  expect(screen.queryByRole('button', { name: 'Add SAML application' })).toBeNull()
  expect(screen.queryByRole('button', { name: 'Actions for Wiki' })).toBeNull()
})
