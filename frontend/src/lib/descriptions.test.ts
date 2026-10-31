import { expect, it } from 'vitest'
import { describe, type PermissionDescription } from './descriptions'

const items: PermissionDescription[] = [
  { permission: 'notes:read', locale: '', display_name: 'Read notes', description: 'See your notes.' },
  { permission: 'notes:read', locale: 'es', display_name: 'Leer notas', description: 'Ver tus notas.' },
  { permission: 'notes:write', locale: '', display_name: 'Write notes', description: '' },
]

it('resolves exact locale, then base language, then the default, then the raw name', () => {
  expect(describe(items, 'notes:read', 'es').display_name).toBe('Leer notas')
  expect(describe(items, 'notes:read', 'es-PE')).toMatchObject({ display_name: 'Leer notas', description: 'Ver tus notas.', described: true })
  expect(describe(items, 'notes:read', 'fr').display_name).toBe('Read notes')
  expect(describe(items, 'notes:write', 'es').display_name).toBe('Write notes')
  expect(describe(items, 'notes:delete', 'es')).toEqual({ name: 'notes:delete', display_name: 'notes:delete', description: '', described: false })
  expect(describe(undefined, 'notes:read', 'en')).toMatchObject({ display_name: 'notes:read', described: false })
})
