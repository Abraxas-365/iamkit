// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from '../lib/auth'
import App from '../App'

const fetchMock = vi.fn()
let status: Record<string, unknown>
let posted: Record<string, string>[]
beforeEach(() => {
  status = { set: true, usable: true, fresh: false, mode: 'enabled' }
  posted = []
  vi.stubGlobal('fetch', fetchMock)
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({ matches: false, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  fetchMock.mockImplementation(async (url: string, init: RequestInit = {}) => {
    const path = url.replace('/management/v1', '').split('?')[0]
    if (path === '/login-options') return Response.json({ password: true, password_mode: 'enabled', providers: [] })
    if (path === '/me') return Response.json({ operator_id: 'op1', workspace_id: 'ws1', role: 'owner', method: 'password' })
    if (path === '/password' && init.method === 'POST') { posted.push(JSON.parse(String(init.body))); return new Response(null, { status: 204 }) }
    if (path === '/password') return Response.json(status)
    return Response.json([])
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.resetAllMocks() })
function open() {
  render(<MemoryRouter initialEntries={['/settings']}><AuthProvider><App /></AuthProvider></MemoryRouter>)
}

it('changes the password with the current one', async () => {
  const user = userEvent.setup()
  open()
  await user.type(await screen.findByLabelText('Current password'), 'old password!!')
  await user.type(screen.getByLabelText('New password'), 'a brand new password')
  await user.type(screen.getByLabelText('Confirm password'), 'a brand new password')
  await user.click(screen.getByRole('button', { name: 'Update password' }))
  await waitFor(() => expect(posted).toEqual([{ current_password: 'old password!!', password: 'a brand new password' }]))
})

it('sets a first password after a recent sign-in without asking for one', async () => {
  status = { set: false, usable: true, fresh: true, mode: 'break_glass' }
  const user = userEvent.setup()
  open()
  await user.type(await screen.findByLabelText('New password'), 'a brand new password')
  expect(screen.queryByLabelText('Current password')).toBeNull()
  await user.type(screen.getByLabelText('Confirm password'), 'a brand new password')
  await user.click(screen.getByRole('button', { name: 'Set password' }))
  await waitFor(() => expect(posted).toEqual([{ password: 'a brand new password' }]))
})

it('asks to sign in again before setting a first password', async () => {
  status = { set: false, usable: true, fresh: false, mode: 'break_glass' }
  open()
  expect(await screen.findByRole('button', { name: 'Sign in again' })).toBeTruthy()
  expect(screen.queryByLabelText('New password')).toBeNull()
})

it('explains single sign-on to operators without emergency access', async () => {
  status = { set: false, usable: false, fresh: true, mode: 'break_glass' }
  open()
  expect(await screen.findByRole('heading', { name: 'You sign in with single sign-on' })).toBeTruthy()
})
