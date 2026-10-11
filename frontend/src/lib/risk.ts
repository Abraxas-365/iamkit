// Shapes and wording of the security APIs (internal/iam/risk): bot
// protection (CAPTCHA), the risk policy, restrictions and the sign-in log.
import { t } from '@/lib/i18n'

/** GET|PUT …/captcha (risk.CaptchaConfig); the secret is never returned. */
export interface CaptchaConfig {
  environment_id: string; provider: string; site_key: string; has_secret: boolean
  hosted: boolean; headless: boolean; hostnames: string[]; updated_at: string
}

export interface Thresholds {
  ip_failures_per_hour: number; ip_distinct_logins_per_hour: number; user_failures_per_hour: number
  stale_after_days: number; travel_speed_kmh: number
}

/** GET|PUT …/risk-policy (risk.Policy). `saved` is false for the default. */
export interface RiskPolicy {
  actions: Record<string, string>; thresholds: Thresholds
  notify_user: boolean; block_if_unverifiable: boolean; saved: boolean; updated_at?: string
}

/** GET …/risk/status (risk.Status): what the deployment offers. */
export interface RiskStatus {
  geoip: { source: string; database?: string; header?: string; build_date?: string; countries: boolean; travel: boolean; error?: string }
  captcha: boolean; risk_signals: boolean
}

export interface Restriction { id: string; kind: string; value: string; action: string; note: string; created_at: string }

/** One recorded sign-in attempt (risk.Attempt). */
export interface SignInAttempt {
  id: string; user_id?: string; organization_id?: string; ip?: string; user_agent?: string; country?: string
  latitude?: number; longitude?: number; device: boolean; method: string; surface: string; outcome: string
  reason?: string; detections: string[] | null; action: string; captcha?: string; created_at: string
}

export interface KnownDevice { first_seen_at: string; last_seen_at: string; last_ip?: string; last_country?: string; user_agent?: string }

export const detections = ['ip_velocity', 'user_brute_force', 'impossible_travel', 'new_device', 'stale_account'] as const

/** The actions each detection may take (risk.AllowedActions). */
export const allowedActions: Record<string, string[]> = {
  ip_velocity: ['off', 'log', 'challenge', 'block'],
  user_brute_force: ['off', 'log', 'challenge', 'block'],
  impossible_travel: ['off', 'log', 'challenge', 'block'],
  new_device: ['off', 'log', 'notify', 'challenge'],
  stale_account: ['off', 'log', 'notify', 'challenge'],
}

export const detectionLabels: Record<string, string> = {
  ip_velocity: t('IP address velocity'), user_brute_force: t('Brute force on one account'), impossible_travel: t('Impossible travel'),
  new_device: t('New device'), stale_account: t('Stale account'),
}
export const detectionHints: Record<string, string> = {
  ip_velocity: t('Many failed sign-ins, or many different logins tried, from one IP address within an hour.'),
  user_brute_force: t('Many failed sign-ins on one login within an hour, from any address.'),
  impossible_travel: t('The previous sign-in was too far away for the time between them. Needs GeoIP with coordinates (a City database).'),
  new_device: t('A device the user has never signed in from. Needs the hosted page or a device_id from your sign-in UI.'),
  stale_account: t('The user has not signed in for a long time.'),
}
export const actionLabels: Record<string, string> = {
  none: t('None'), off: t('Off'), log: t('Log only'), notify: t('Notify the user'), challenge: t('Challenge with an emailed code'), block: t('Block'),
}
export const outcomeLabels: Record<string, string> = {
  success: t('Success'), failure: t('Failure'), blocked: t('Blocked'), challenged: t('Challenged'), captcha_failed: t('CAPTCHA failed'),
}
export const outcomes = ['success', 'failure', 'blocked', 'challenged', 'captcha_failed'] as const
export const outcomeTones: Record<string, string> = {
  success: 'bg-success/10 text-success', failure: '', blocked: 'bg-destructive/10 text-destructive',
  challenged: 'bg-warning/10 text-warning', captcha_failed: 'bg-warning/10 text-warning',
}
export const methodLabels: Record<string, string> = {
  password: t('Password'), code: t('Email code'), sso: t('Single sign-on'), passkey: t('Passkey'), social: t('Social'), signup: t('Sign-up'),
}
export const surfaceLabels: Record<string, string> = { hosted: t('Hosted page'), headless: t('Your sign-in UI') }
export const captchaLabels: Record<string, string> = { passed: t('Passed'), failed: t('Failed'), unavailable: t('Provider unavailable') }
export const reasonLabels: Record<string, string> = { restriction: t('A deny restriction matched'), detection: t('A detection with the block action fired') }
export const providerLabels: Record<string, string> = { turnstile: t('Cloudflare Turnstile'), hcaptcha: t('hCaptcha') }
export const kindLabels: Record<string, string> = { ip: t('IP address or range'), country: t('Country'), email_domain: t('Email domain') }

const v4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const v6 = /^[0-9a-f:.]+$/i
const domain = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

/** validIP accepts an IPv4/IPv6 address, optionally with a /prefix length. */
export function validIP(value: string): boolean {
  const [address, prefix, ...rest] = value.split('/')
  if (rest.length || !address) return false
  const six = address.includes(':')
  if (prefix !== undefined && (!/^\d{1,3}$/.test(prefix) || Number(prefix) > (six ? 128 : 32))) return false
  if (!six) return v4.test(address)
  return v6.test(address) && address.split('::').length <= 2 && !address.includes(':::') && address.split(':').length <= 8
}

/** restrictionError returns why a restriction's value is wrong, or ''. */
export function restrictionError(kind: string, raw: string): string {
  const value = raw.trim()
  if (!value) return t('Enter a value.')
  if (kind === 'ip') return validIP(value) ? '' : t('Enter an IP address or a CIDR range, e.g. 203.0.113.0/24.')
  if (kind === 'country') return /^[A-Za-z]{2}$/.test(value) ? '' : t('Enter a two-letter ISO country code, e.g. US.')
  const host = value.toLowerCase().replace(/^@/, '')
  return host.length <= 253 && domain.test(host) ? '' : t('Enter a domain name, e.g. example.com.')
}

/** validHostname rejects a CAPTCHA hostname with a scheme, port or path. */
export const validHostname = (host: string) => !!host && host.length <= 253 && !/[/:@ ?#]/.test(host)
