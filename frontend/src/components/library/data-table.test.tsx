// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Link, MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { DataTable } from './patterns'
import { RowActions } from '@/components/ui/menu'

afterEach(cleanup)

function Where() { return <p data-testid="where">{useLocation().pathname}</p> }
function renderTable(onEdit = () => {}) {
  render(<MemoryRouter initialEntries={['/list']}><Routes><Route path="*" element={<>
    <DataTable columns={['Name', 'Actions']} loading={false} error="" retry={() => {}} rowHref={i => `/items/${i + 1}`}
      rows={[1, 2].map(n => [<Link to={`/items/${n}`}>Item {n}</Link>, <RowActions label={`Actions for Item ${n}`} actions={[{ label: 'Edit', onSelect: onEdit }]} />])} />
    <Where />
  </>} /></Routes></MemoryRouter>)
}
const where = () => screen.getByTestId('where').textContent

it('opens the item when its row is clicked', async () => {
  renderTable()
  await userEvent.click(screen.getByText('Item 2').closest('tr')!.querySelector('td')!)
  expect(where()).toBe('/items/2')
})

it('keeps controls inside a row from opening it', async () => {
  let edited = 0
  renderTable(() => { edited++ })
  await userEvent.click(screen.getByRole('button', { name: 'Actions for Item 1' }))
  await userEvent.click(await screen.findByRole('menuitem', { name: 'Edit' }))
  expect(edited).toBe(1)
  expect(where()).toBe('/list')
})

it('reaches and opens rows from the keyboard, one tab stop per control', async () => {
  const user = userEvent.setup()
  renderTable()
  await user.tab()
  expect(document.activeElement?.textContent).toBe('Item 1')
  await user.tab()
  expect(document.activeElement?.getAttribute('aria-label')).toBe('Actions for Item 1')
  await user.tab()
  expect(document.activeElement?.textContent).toBe('Item 2')
  await user.keyboard('{Enter}')
  expect(where()).toBe('/items/2')
})

it('shows the empty state instead of an empty table', () => {
  render(<MemoryRouter><DataTable columns={['Name']} loading={false} error="" retry={() => {}} rows={[]} empty={<p>Nothing here yet</p>} /></MemoryRouter>)
  expect(screen.getByText('Nothing here yet')).toBeTruthy()
  expect(screen.queryByRole('table')).toBeNull()
})
