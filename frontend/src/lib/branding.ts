// Hosted login branding: the environment default and per-client styles.
export type Mode = 'light' | 'dark' | 'adaptive'
export type Scheme = 'light' | 'dark'
export interface Palette { primary: string; background: string; card: string; text: string; header: string }
export interface FooterLink { label: string; url: string }
export interface Theme {
  mode: Mode; radius: number; spacing: 'compact' | 'normal' | 'roomy'; align: 'center' | 'left' | 'right'
  light: Palette; dark: Palette
  logo_dark_url: string; favicon_url: string; logo_position: 'card' | 'header'
  header: { show: boolean }; footer: { text: string; links: FooterLink[] }
}
export interface Branding {
  environment_id?: string; client_id?: string
  display_name: string; logo_url: string; accent_color: string
  theme: Theme; updated_at?: string
}

export const pages = [
  ['identify', 'Sign in'], ['password', 'Password'], ['code', 'Email code'], ['reset', 'Reset password'],
  ['organization', 'Choose organization'], ['mfa', 'Two-step verification'], ['enroll', 'Set up authenticator'],
  ['recovery', 'Recovery codes'], ['invite', 'Invitation'], ['message', 'Message'],
] as const
export type Page = typeof pages[number][0]

// Defaults the hosted pages use for empty colors (see hostedhttp/brand.go).
export const defaults: Record<Scheme, Palette> = {
  light: { primary: '#2563eb', background: '#f5f5f7', card: '#ffffff', text: '#1d1d1f', header: '' },
  dark: { primary: '', background: '#0f1115', card: '#1a1d23', text: '#f2f2f3', header: '' },
}
const emptyPalette = (): Palette => ({ primary: '', background: '', card: '', text: '', header: '' })
export function emptyBranding(): Branding {
  return {
    display_name: '', logo_url: '', accent_color: '',
    theme: { mode: 'light', radius: 12, spacing: 'normal', align: 'center', light: emptyPalette(), dark: emptyPalette(), logo_dark_url: '', favicon_url: '', logo_position: 'card', header: { show: false }, footer: { text: '', links: [] } },
  }
}

// normalize fills what an older server or row may omit.
export function normalize(b: Partial<Branding>): Branding {
  const base = emptyBranding()
  const t: Partial<Theme> = b.theme ?? {}
  return {
    ...base, ...b,
    theme: {
      ...base.theme, ...t,
      light: { ...base.theme.light, ...t.light }, dark: { ...base.theme.dark, ...t.dark },
      header: { ...base.theme.header, ...t.header },
      footer: { text: t.footer?.text ?? '', links: t.footer?.links ?? [] },
    },
  }
}

// body is what the API stores: the style only (no ids or timestamps).
// accent_color follows theme.light.primary on the server.
export function body(b: Branding) {
  return { display_name: b.display_name, logo_url: b.logo_url, accent_color: b.theme.light.primary, theme: b.theme }
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
  if (contrast(p.text, p.card) < 4.5) out.push(`Text on card contrast is ${contrast(p.text, p.card).toFixed(1)}:1 (needs 4.5:1).`)
  if (contrast(p.primary, p.card) < 3) out.push(`Primary on card contrast is ${contrast(p.primary, p.card).toFixed(1)}:1 (links need 3:1).`)
  if (contrast(readable(p.primary), p.primary) < 4.5) out.push('Button text is hard to read on the primary color.')
  return out
}
