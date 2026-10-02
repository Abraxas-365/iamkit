import { t } from '@/lib/i18n'
// Hosted login branding: the environment default and per-client styles.
export type Mode = 'light' | 'dark' | 'adaptive'
export type Scheme = 'light' | 'dark'
export interface Palette { primary: string; background: string; card: string; text: string; header: string }
export interface FooterLink { label: string; url: string }
/** A typeface: 'system' (default; for headings, the text font), one IAMKit serves itself, or 'custom' with an https .woff2 url. */
export interface Font { family: string; url?: string }
export const fonts = [
  ['system', t('System (default)')], ['inter', t('Inter')], ['roboto', t('Roboto')], ['open-sans', t('Open Sans')], ['lora', t('Lora (serif)')], ['custom', t('Custom (.woff2 URL)')],
] as const
/** Policy links shown on the sign-in and sign-up pages; a client style's empty links inherit the environment's. */
export interface Legal { privacy_url: string; terms_url: string; help_url: string; support_email: string }
export interface Theme {
  mode: Mode; radius: number; spacing: 'compact' | 'normal' | 'roomy'; align: 'center' | 'left' | 'right'
  light: Palette; dark: Palette
  logo_dark_url: string; favicon_url: string; logo_position: 'card' | 'header'
  header: { show: boolean }; footer: { text: string; links: FooterLink[] }
  /** HTTPS image behind the form, tinted by background_overlay % (0-90) of the background color. */
  background_image_url: string; background_overlay: number
  font: Font; heading_font: Font
}
export interface Branding {
  environment_id?: string; client_id?: string
  display_name: string; logo_url: string; accent_color: string
  theme: Theme; updated_at?: string
  /** Default language of the hosted pages and emails ('' = automatic; on a client style, the environment's). */
  locale?: string
  /** Languages the hosted pages may use (empty = every available one); environment default only. */
  languages?: string[]
  legal?: Legal
}

export const pages = [
  ['identify', t('Sign in')], ['password', t('Password')], ['code', t('Email code')], ['reset', t('Reset password')],
  ['organization', t('Choose organization')], ['mfa', t('Two-step verification')], ['enroll', t('Set up authenticator')],
  ['recovery', t('Recovery codes')], ['invite', t('Invitation')], ['message', t('Message')],
  ['signup', t('Create account')], ['signup-code', t('Confirm email')],
] as const
export type Page = typeof pages[number][0]

// PreviewMethods is which sign-in methods a preview shows (sign-in and
// password pages only); the server checks it like real client options.
export interface PreviewButton { name: string; provider: string }
export interface PreviewMethods { password: boolean; email_code: boolean; organization_sso: boolean; connections: PreviewButton[] }
// sampleButtons stand in when the environment has no social login yet.
export const sampleButtons: PreviewButton[] = [
  { name: 'Google', provider: 'google' }, { name: 'Microsoft', provider: 'microsoft' },
  { name: 'GitHub', provider: 'github' }, { name: 'Apple', provider: 'apple' },
]
export const methodPages: readonly Page[] = ['identify', 'password']
export const emailForm = (m: PreviewMethods) => m.password || m.email_code || m.organization_sso

// Defaults the hosted pages use for empty colors (see hostedhttp/brand.go).
export const defaults: Record<Scheme, Palette> = {
  light: { primary: '#2563eb', background: '#f5f5f7', card: '#ffffff', text: '#1d1d1f', header: '' },
  dark: { primary: '', background: '#0f1115', card: '#1a1d23', text: '#f2f2f3', header: '' },
}
export const emptyLegal = (): Legal => ({ privacy_url: '', terms_url: '', help_url: '', support_email: '' })
const emptyPalette = (): Palette => ({ primary: '', background: '', card: '', text: '', header: '' })
export function emptyBranding(): Branding {
  return {
    display_name: '', logo_url: '', accent_color: '',
    theme: { mode: 'light', radius: 12, spacing: 'normal', align: 'center', light: emptyPalette(), dark: emptyPalette(), logo_dark_url: '', favicon_url: '', logo_position: 'card', header: { show: false }, footer: { text: '', links: [] }, background_image_url: '', background_overlay: 0, font: { family: 'system' }, heading_font: { family: 'system' } },
    legal: emptyLegal(),
  }
}

// normalize fills what an older server or row may omit.
export function normalize(b: Partial<Branding>): Branding {
  const base = emptyBranding()
  const th: Partial<Theme> = b.theme ?? {}
  return {
    ...base, ...b,
    theme: {
      ...base.theme, ...th,
      light: { ...base.theme.light, ...th.light }, dark: { ...base.theme.dark, ...th.dark },
      header: { ...base.theme.header, ...th.header },
      footer: { text: th.footer?.text ?? '', links: th.footer?.links ?? [] },
      font: { family: th.font?.family || 'system', ...(th.font?.url && { url: th.font.url }) },
      heading_font: { family: th.heading_font?.family || 'system', ...(th.heading_font?.url && { url: th.heading_font.url }) },
    },
    legal: { ...emptyLegal(), ...b.legal },
  }
}

// body is what the API stores: the style only (no ids or timestamps).
// accent_color follows theme.light.primary on the server. The enabled
// languages belong to the environment default only; an omitted language
// keeps the stored one.
export function body(b: Branding) {
  return {
    display_name: b.display_name, logo_url: b.logo_url, accent_color: b.theme.light.primary, theme: b.theme,
    ...(b.locale !== undefined && { locale: b.locale }),
    ...(b.languages !== undefined && !b.client_id && { languages: b.languages }),
    ...(b.legal !== undefined && { legal: b.legal }),
  }
}

export function same(a: Branding, b: Branding) { return JSON.stringify(body(a)) === JSON.stringify(body(b)) }

// Resolved colors of a scheme, as the pages compute them.
export function resolved(b: Branding, scheme: Scheme): Palette {
  // Half-typed colors count as empty until they are valid.
  const ok = (c: string) => hex.test(c) ? c : ''
  const own = b.theme[scheme]
  const d = defaults[scheme]
  const lightPrimary = ok(b.theme.light.primary) || ok(b.accent_color) || defaults.light.primary
  const card = ok(own.card) || d.card
  return {
    primary: scheme === 'light' ? lightPrimary : ok(own.primary) || lightPrimary,
    background: ok(own.background) || d.background, card, text: ok(own.text) || d.text, header: ok(own.header) || card,
  }
}

export const hex = /^#[0-9a-fA-F]{6}$/

function luminance(color: string) {
  const c = [1, 3, 5].map(i => parseInt(color.slice(i, i + 2), 16) / 255).map(v => v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4)
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
}
// contrast is the WCAG contrast ratio of two #rrggbb colors.
export function contrast(a: string, b: string) {
  if (!hex.test(a) || !hex.test(b)) return 21
  const [x, y] = [luminance(a), luminance(b)].sort((m, n) => n - m)
  return (x + 0.05) / (y + 0.05)
}
// readable is the button text color the pages pick for a background.
export function readable(color: string) { return hex.test(color) && luminance(color) > 0.179 ? '#000000' : '#ffffff' }

// warnings lists low-contrast pairs of a scheme.
export function warnings(b: Branding, scheme: Scheme): string[] {
  const p = resolved(b, scheme)
  const out: string[] = []
  if (contrast(p.text, p.card) < 4.5) out.push(t('Text on card contrast is {{ratio}}:1 (needs 4.5:1).', { ratio: contrast(p.text, p.card).toFixed(1) }))
  if (contrast(p.primary, p.card) < 3) out.push(t('Primary on card contrast is {{ratio}}:1 (links need 3:1).', { ratio: contrast(p.primary, p.card).toFixed(1) }))
  if (contrast(readable(p.primary), p.primary) < 4.5) out.push(t('Button text is hard to read on the primary color.'))
  return out
}
