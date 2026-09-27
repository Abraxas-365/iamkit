// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
const key = 'ik_mgmt_' + 'k'.repeat(40)
beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  // The management API authenticates keys via X-API-Key only (docs/start/docker-quickstart.md).
  fetchMock.mockImplementation(async (_url: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers)
    if (headers.get('X-API-Key') !== key) return Response.json({ error: { message: 'management credential required' } }, { status: 401 })
    return init.method === 'POST' ? new Response(null, { status: 204 }) : Response.json({ operator_id: 'op1', workspace_id: 'ws1', role: 'viewer' })
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })

it('sets an operator password with the management key in X-API-Key', async () => {
  const user = userEvent.setup()
  render(<MemoryRouter initialEntries={['/setup']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
  await user.type(await screen.findByLabelText('Management API key'), key)
  await user.click(screen.getByRole('button', { name: 'Continue' }))
  await user.type(await screen.findByLabelText('New password'), 'Viewer-Passw0rd-2026')
  await user.type(screen.getByLabelText('Confirm password'), 'Viewer-Passw0rd-2026')
  await user.click(screen.getByRole('button', { name: 'Set password' }))
  await screen.findByText(/Password set successfully/)
  const post = fetchMock.mock.calls.find(([url, init]) => String(url).endsWith('/password') && init?.method === 'POST')
  expect(new Headers(post![1].headers).get('Authorization')).toBeNull()
})
