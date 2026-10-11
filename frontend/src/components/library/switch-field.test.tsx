// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SwitchField } from './patterns'

afterEach(cleanup)

it('names the switch by its label and describes it by its hint', async () => {
  let checked = false
  render(<SwitchField label="Join by verified domain" hint="People with a verified email join." onCheckedChange={v => { checked = v }} />)
  const control = screen.getByRole('switch', { name: 'Join by verified domain' })
  expect(control).toHaveProperty('checked', false)
  expect(control.getAttribute('aria-describedby')).toBeTruthy()
  expect(document.getElementById(control.getAttribute('aria-describedby')!)?.textContent).toBe('People with a verified email join.')
  await userEvent.click(screen.getByText('Join by verified domain'))
  expect(checked).toBe(true)
})
