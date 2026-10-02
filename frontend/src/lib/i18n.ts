// Console i18n. Keys are the English text (`t('Create project')`); the
// catalogs in src/locales map them to a language, and a missing entry shows
// the English key. Plural keys add i18next suffixes (`_one`, `_other`, …)
// in every catalog, including en.json. `npm run i18n` regenerates en.json
// from the sources; src/locales.test.ts keeps the catalogs complete.
//
// The language is chosen once, before the app is imported (main.tsx awaits
// loadLanguage), so module-level t() calls see it; changing it reloads the
// page. Order: the operator's saved preference (operators.locale, mirrored
// in localStorage), else the browser's languages, else English.
import i18next from 'i18next'
import { createElement, Fragment, type ReactNode } from 'react'
import en from '@/locales/en.json'

/** Languages the console is translated into. */
export const LANGUAGES = [
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Español' },
] as const
export type Language = (typeof LANGUAGES)[number]['code']
const STORAGE = 'iamkit-locale'
const catalogs: Record<Language, () => Promise<{ default: Record<string, string> }>> = {
  en: async () => ({ default: en }),
  es: () => import('@/locales/es.json'),
}

const i18n = i18next.createInstance()
void i18n.init({
  lng: 'en', fallbackLng: 'en', initAsync: false, resources: { en: { translation: en } },
  // English text is the key: no nesting or namespaces, and React escapes.
  keySeparator: false, nsSeparator: false, returnEmptyString: false, interpolation: { escapeValue: false },
})

/** Translates English text; `{{name}}` placeholders take values, `count` picks the plural. */
export function t(key: string, values?: Record<string, unknown>): string {
  return values ? i18n.t(key, values) : i18n.t(key)
}

/** rich translates a sentence whose placeholders are elements
 * (`rich('Set {{name}} on the server.', { name: <code>X</code> })`), so
 * translators can move them; a numeric `count` picks the plural. */
export function rich(key: string, values: Record<string, ReactNode>): ReactNode {
  const template = i18n.t(key, { skipInterpolation: true, ...(typeof values.count === 'number' && { count: values.count }) })
  const parts = template.split(/\{\{\s*([\w.]+)\s*\}\}/)
  return createElement(Fragment, null, ...parts.map((part, i) => i % 2 ? values[part] ?? null : part))
}

/** The language in use, also for Intl formatting. */
export function language(): Language { return i18n.language as Language }

/** match picks the console language for a BCP 47 tag ('es-MX' → 'es'). */
export function match(tag: string | null | undefined): Language | undefined {
  const base = tag?.toLowerCase().split('-')[0]
  return LANGUAGES.find(l => l.code === base)?.code
}

/** The stored choice, else the browser's first supported language, else English. */
export function preferred(): Language {
  let saved: string | null = null
  try { saved = localStorage.getItem(STORAGE) } catch { /* storage blocked */ }
  return match(saved) ?? (typeof navigator === 'undefined' ? undefined : navigator.languages?.map(match).find(Boolean)) ?? 'en'
}

/** Loads a language's catalog and switches to it. */
export async function loadLanguage(code: Language = preferred()): Promise<void> {
  if (code !== 'en' && !i18n.hasResourceBundle(code, 'translation')) i18n.addResourceBundle(code, 'translation', (await catalogs[code]()).default)
  await i18n.changeLanguage(code)
  document.documentElement.lang = code
}

/** Remembers a language in this browser (null: follow the browser); returns whether it differs from the current one. */
export function remember(code: string | null | undefined): boolean {
  const lang = match(code)
  try { if (lang) localStorage.setItem(STORAGE, lang); else localStorage.removeItem(STORAGE) } catch { /* storage blocked */ }
  return (lang ?? preferred()) !== language()
}

/** The language saved in this browser, if any. */
export function saved(): Language | undefined {
  try { return match(localStorage.getItem(STORAGE)) } catch { return undefined }
}

/** Formats a date and time in the console language. */
export function formatDateTime(value: string | number | Date, options: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' }): string {
  return new Date(value).toLocaleString(language(), options)
}

/** Formats a number in the console language. */
export function formatNumber(value: number, options?: Intl.NumberFormatOptions): string {
  return new Intl.NumberFormat(language(), options).format(value)
}
