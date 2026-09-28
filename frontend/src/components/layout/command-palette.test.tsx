// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { CommandPalette } from './command-palette'

const fetchMock = vi.fn()
const envBase = '/projects/p1/environments/env1'

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockImplementation(async (url: string) => {
    const [path, qs] = url.replace('/management/v1', '').split('?')
    const search = new URLSearchParams(qs).get('search') ?? ''
    const items = path === '/environments/env1/users' && 'alice'.includes(search) ? [{ id: 'u1', name: 'Alice', email: 'alice@example.com' }]
      : path === '/environments/env1/organizations' && 'acme'.startsWith(search) ? [{ id: 'o1', name: 'Acme' }] : []
    return Response.json({ items, page: { total: items.length, limit: 5, offset: 0 } })
  })
})
afterEach(() => { cleanup(); vi.unstubAllGlobals(); fetchMock.mockReset() })

function Where() { return <p data-testid="where">{useLocation().pathname}</p> }
function renderPalette() {
  render(<MemoryRouter initialEntries={[envBase]}><Routes><Route path="*" element={<>
    <CommandPalette envBase={envBase} environment="env1" pages={[{ to: `${envBase}/users`, label: 'Users', group: 'Pages' }, { to: `${envBase}/audit-events`, label: 'Audit events', group: 'Pages' }]} />
    <Where />
  </>} /></Routes></MemoryRouter>)
}

it('opens with Ctrl+K and jumps to a page with the keyboard', async () => {
  const user = userEvent.setup()
  renderPalette()
  await user.keyboard('{Control>}k{/Control}')
  const input = await screen.findByRole('combobox')
  await user.type(input, 'audit')
  expect(screen.getAllByRole('option').map(o => o.textContent)).toEqual(['Audit events'])
  await user.keyboard('{Enter}')
  expect(screen.getByTestId('where').textContent).toBe(`${envBase}/audit-events`)
  expect(screen.queryByRole('combobox')).toBeNull()
})

it('searches users and organizations by name and opens the chosen one', async () => {
  const user = userEvent.setup()
  renderPalette()
  await user.click(screen.getByRole('button', { name: /search/i }))
  await user.type(screen.getByRole('combobox'), 'al')
  await screen.findByRole('option', { name: /Alice/ })
  expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/environments/env1/users?limit=5&search=al'))).toBe(true)
  await user.click(screen.getByRole('option', { name: /Alice/ }))
  expect(screen.getByTestId('where').textContent).toBe(`${envBase}/users/u1`)
})

it('explains when nothing matches', async () => {
  const user = userEvent.setup()
  renderPalette()
  await user.keyboard('{Control>}k{/Control}')
  await user.type(await screen.findByRole('combobox'), 'zzz')
  await waitFor(() => expect(screen.getByText('Nothing matches “zzz”.')).toBeTruthy())
})
