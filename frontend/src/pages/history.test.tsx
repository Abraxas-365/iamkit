// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { changeValue, HistorySection } from './history'

const fetchMock = vi.fn()
let urls: string[]

beforeEach(() => {
  urls = []
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockImplementation(async (url: string) => {
    urls.push(url)
    const before = new URL(url, 'http://x').searchParams.get('before')
    const page = before
      ? { items: [{ id: 3, type: 'user.created', actor: { kind: 'operator', id: 'op1' }, occurred_at: '2026-01-01T00:00:00Z' }], next: 0 }
      : { items: [{ id: 9, type: 'user.updated', actor: { kind: 'service_account', id: 'sa1' }, data: { changes: { name: ['Al', 'Alice'], 'metadata.plan': [null, 'pro'] } }, occurred_at: '2026-01-02T00:00:00Z' }], next: 9 }
    return new Response(JSON.stringify(page), { status: 200, headers: { 'Content-Type': 'application/json' } })
  })
})

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('renders changes and pages back with before', async () => {
  render(<MemoryRouter><HistorySection path="/environments/env1/users/u1" /></MemoryRouter>)
  expect(await screen.findByText('User updated')).toBeTruthy()
  expect(urls[0]).toContain('/environments/env1/users/u1/history?limit=20')
  expect(screen.getByText('metadata.plan')).toBeTruthy()
  expect(screen.getByText('Al')).toBeTruthy()
  expect(screen.getByText('Alice')).toBeTruthy()
  expect(screen.getByText('Service account')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'Older history' }))
  expect(await screen.findByText('User created')).toBeTruthy()
  await waitFor(() => expect(urls.at(-1)).toContain('before=9'))
  expect((screen.getByRole('button', { name: 'Older history' }) as HTMLButtonElement).disabled).toBe(true)
})

it('formats change values', () => {
  expect(changeValue(null)).toBe('∅')
  expect(changeValue('')).toBe('∅')
  expect(changeValue(true)).toBe('true')
  expect(changeValue(['a'])).toBe('["a"]')
})
