// @vitest-environment jsdom
import { afterAll, describe, expect, it } from 'vitest'
import { loadLanguage, t } from '@/lib/i18n'
import en from '@/locales/en.json'
import es from '@/locales/es.json'

const catalogs: Record<string, Record<string, string>> = { es }
const placeholders = (text: string) => [...text.matchAll(/\{\{\s*([\w.]+)\s*\}\}/g)].map(m => m[1]).sort()
// i18next plural forms beyond en's _one/_other (es adds _many).
const base = (key: string) => key.replace(/_(zero|two|few|many)$/, '_other')

describe('loadLanguage', () => {
  afterAll(() => loadLanguage('en'))
  it('translates and pluralizes in Spanish', async () => {
    await loadLanguage('es')
    expect(t('Save')).toBe('Guardar')
    expect(t('{{count}} attempts', { count: 1 })).toBe('1 intento')
    expect(t('{{count}} attempts', { count: 3 })).toBe('3 intentos')
    expect(t('{{count}} attempts', { count: 1_000_000 })).toBe('1000000 intentos')
    expect(document.documentElement.lang).toBe('es')
  })
})

describe.each(Object.entries(catalogs))('%s catalog', (_, catalog) => {
  it('translates every console key', () => {
    expect(Object.keys(en).filter(k => !(k in catalog))).toEqual([])
  })

  it('has no keys the console no longer uses', () => {
    expect(Object.keys(catalog).filter(k => !(base(k) in en))).toEqual([])
  })

  it('keeps the placeholders of the English text', () => {
    const wrong = Object.entries(catalog).filter(([k, v]) => {
      const english = (en as Record<string, string>)[base(k)]
      return english !== undefined && placeholders(english).join() !== placeholders(v).join()
    })
    expect(wrong.map(([k]) => k)).toEqual([])
  })
})
