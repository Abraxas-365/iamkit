// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CollapsibleScopes } from './collapsible-scopes'

afterEach(cleanup)

const scopes = ['api:read', 'api:write', 'api:delete', 'api:admin', 'api:audit']

it.each([0, 1, 3])('shows %i scopes without an expansion button', count => {
  render(<CollapsibleScopes scopes={scopes.slice(0, count)} />)
  scopes.slice(0, count).forEach(scope => expect(screen.getByText(scope)).toBeTruthy())
  expect(screen.queryByRole('button')).toBeNull()
})

it('previews three scopes and expands and collapses the full list', async () => {
  const user = userEvent.setup()
  render(<CollapsibleScopes scopes={scopes} />)
  scopes.slice(0, 3).forEach(scope => expect(screen.getByText(scope)).toBeTruthy())
  expect(screen.queryByText(scopes[3])).toBeNull()
  expect(screen.queryByText(scopes[4])).toBeNull()
  const toggle = screen.getByRole('button', { name: '+2 more' })
  expect(toggle.getAttribute('aria-expanded')).toBe('false')
  expect(document.getElementById(toggle.getAttribute('aria-controls')!)).toBeTruthy()

  await user.click(toggle)
  scopes.forEach(scope => expect(screen.getByText(scope)).toBeTruthy())
  expect(toggle.getAttribute('aria-expanded')).toBe('true')

  await user.click(screen.getByRole('button', { name: 'Show less' }))
  expect(screen.queryByText(scopes[3])).toBeNull()
  expect(screen.queryByText(scopes[4])).toBeNull()
  expect(screen.getByRole('button', { name: '+2 more' })).toBeTruthy()
})

it('keeps separate lists independently expandable using the keyboard', async () => {
  const user = userEvent.setup()
  render(<>
    <section aria-label="First"><CollapsibleScopes scopes={scopes} /></section>
    <section aria-label="Second"><CollapsibleScopes scopes={scopes} /></section>
  </>)
  await user.tab()
  await user.keyboard('{Enter}')
  expect(within(screen.getByRole('region', { name: 'First' })).getByText(scopes[4])).toBeTruthy()
  expect(within(screen.getByRole('region', { name: 'Second' })).queryByText(scopes[4])).toBeNull()
})
