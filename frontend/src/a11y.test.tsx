// @vitest-environment jsdom
// Accessibility smoke test: renders the console's main page types with
// realistic data and fails on serious or critical axe-core violations.
// Color contrast needs real layout, so it is checked with Lighthouse in the
// browser instead (jsdom does not render).
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import axe from 'axe-core'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from './lib/auth'
import App from './App'

const fetchMock = vi.fn()
const env = '/environments/env1'
const base = '/projects/project1/environments/env1'
const page = (items: unknown[]) => ({ items, page: { total: items.length, limit: 50, offset: 0 } })
const user = { id: 'u1', name: 'Jane Doe', email: 'jane@example.com', active: true, created_at: '2026-09-01T00:00:00Z', metadata: {} }
const org = { id: 'o1', name: 'Acme', active: true, created_at: '2026-09-01T00:00:00Z', member_count: 1 }
const client = { id: 'c1', application_id: 'a1', application_name: 'Web', resource_id: 'r1', resource_name: 'Billing', redirect_uris: ['https://app.example/callback'], public: true, hosted_login: true, active: true }

const fixtures: Record<string, unknown> = {
  '/me': { operator_id: 'op1', workspace_id: 'ws1', role: 'owner' },
  '/projects': [{ id: 'project1', name: 'Billing' }],
  '/projects/project1/environments': [{ id: 'env1', name: 'Production' }],
  '/operators': page([{ id: 'op1', email: 'owner@example.com', role: 'owner', active: true }, { id: 'op2', email: 'ops@example.com', role: 'admin', active: true }]),
  [`${env}/users`]: page([user]),
  [`${env}/users/u1`]: user,
  [`${env}/users/u1/factors`]: { factors: [], recovery_codes_remaining: 0 },
  [`${env}/organizations`]: page([org]),
  [`${env}/organizations/o1`]: org,
  [`${env}/organizations/o1/members`]: page([{ user_id: 'u1', user_name: 'Jane Doe', user_email: 'jane@example.com', active: true, joined_at: '2026-09-01T00:00:00Z' }]),
  [`${env}/oauth-clients`]: page([client]),
  [`${env}/oauth-clients/c1`]: client,
  [`${env}/login-settings`]: { environment_id: 'env1', display_name: 'Acme', logo_url: '', accent_color: '' },
  [`${env}/audit-events`]: page([{ id: 'e1', actor: 'owner@example.com', action: 'organization.updated', target_id: 'o1', target_label: 'Acme', created_at: '2026-09-27T00:00:00Z' }]),
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (path.endsWith('/login-settings/preview')) return Response.json({ html: '<!doctype html><title>preview</title>' })
    if (init.method && init.method !== 'GET') return new Response(null, { status: 204 })
    return Response.json(path in fixtures ? fixtures[path] : page([]))
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

async function violations() {
  const result = await axe.run(document.body, {
    // jsdom has no layout: contrast and target-size cannot be measured here.
    rules: { 'color-contrast': { enabled: false }, 'target-size': { enabled: false } },
    resultTypes: ['violations'],
    // The branding preview iframe holds server-rendered hosted pages (tested
    // separately); jsdom cannot message into frames.
    iframes: false,
  })
  return result.violations
    .filter(v => v.impact === 'serious' || v.impact === 'critical')
    .map(v => `${v.id}: ${v.help}\n  ${v.nodes.slice(0, 3).map(n => n.html.slice(0, 160)).join('\n  ')}`)
}

const pages: [string, string, string][] = [
  ['users list', `${base}/users`, 'Jane Doe'],
  ['user detail', `${base}/users/u1`, 'jane@example.com'],
  ['organization members', `${base}/organizations/o1/members`, 'Jane Doe'],
  ['OAuth clients', `${base}/oauth-clients`, 'Web'],
  ['OAuth client detail', `${base}/oauth-clients/c1`, 'https://app.example/callback'],
  ['audit events', `${base}/audit-events`, 'Acme'],
  ['branding editor', `${base}/hosted-login/default`, 'Default style'],
  ['operators', '/operators', 'ops@example.com'],
]

it.each(pages)('%s has no serious accessibility violations', async (_name, path, ready) => {
  render(<MemoryRouter initialEntries={[path]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
  await screen.findAllByText(ready)
  await waitFor(() => expect(document.querySelector('[role=status]')).toBeNull())
  expect(await violations()).toEqual([])
})

it('the command palette and row menus have no serious accessibility violations', async () => {
  const u = userEvent.setup()
  render(<MemoryRouter initialEntries={[`${base}/users`]}><AuthProvider><App /></AuthProvider></MemoryRouter>)
  await screen.findByText('Jane Doe')
  await u.click(screen.getByRole('button', { name: 'Actions for Jane Doe' }))
  await screen.findAllByRole('menuitem')
  expect(await violations()).toEqual([])
  await u.keyboard('{Escape}')
  await u.keyboard('{Control>}k{/Control}')
  await u.type(await screen.findByRole('combobox'), 'aud')
  await screen.findByRole('option', { name: /Audit/ })
  expect(await violations()).toEqual([])
})
