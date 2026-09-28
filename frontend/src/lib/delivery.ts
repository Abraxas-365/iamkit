// Email delivery settings (see internal/iam/authentication/delivery.go).
export type Provider = 'webhook' | 'smtp' | 'resend'
export type Source = 'environment' | 'global' | 'none'

export interface DeliveryConfig {
  environment_id: string
  provider: Provider
  webhook_url: string
  has_token: boolean
  invitation_url: string
  from_email: string
  from_name: string
  reply_to: string
  smtp_host: string
  smtp_port: number
  smtp_username: string
  smtp_tls: 'starttls' | 'tls' | ''
  has_secret: boolean
  created_at: string
  updated_at: string
}

export interface Attempt {
  source: Source
  purpose: string
  delivered: boolean
  status?: number
  reason?: string
  latency_ms: number
  at: string
}

export interface DeliveryStatus {
  source: Source
  provider?: Provider | ''
  global_configured: boolean
  hosted_invitation_url: string
  last_attempt: Attempt | null
  last_failure: Attempt | null
}

export interface Locale { code: string; name: string }

// Copy is the editable wording of one email; empty fields use the default.
export interface Copy { subject: string; heading: string; body: string; action: string; footer: string }
export const emptyCopy = (): Copy => ({ subject: '', heading: '', body: '', action: '', footer: '' })
// Server limits (authentication.Copy.Validate).
export const copyLimits: Record<keyof Copy, number> = { subject: 200, heading: 200, body: 2000, action: 60, footer: 500 }
// MAX_APP_NAME is the longest brand name (hosted display_name).
export const MAX_APP_NAME = 100

// copyLength counts a field as the server does: trimmed, line breaks as
// "\n", in code points (an emoji is one character, not two UTF-16 units).
export function copyLength(value: string): number {
  return [...value.replace(/\r\n?/g, '\n').trim()].length
}

// overLimit lists the fields longer than the server accepts.
export function overLimit(c: Copy): (keyof Copy)[] {
  return (Object.keys(copyLimits) as (keyof Copy)[]).filter(k => copyLength(c[k]) > copyLimits[k])
}

export interface TemplateSummary { purpose: string; locale: string; customized: boolean; updated_at?: string }
export interface TemplateView extends TemplateSummary { template: Copy; defaults: Copy; placeholders: string[] }
export interface Preview { subject: string; html: string; text: string }

export const PROVIDERS: Record<Provider, { label: string; description: string }> = {
  webhook: { label: 'Webhook', description: 'Your service receives the code as JSON and sends the email.' },
  smtp: { label: 'SMTP', description: 'IAMKit writes the email and sends it through your mail server.' },
  resend: { label: 'Resend', description: 'IAMKit writes the email and sends it with your Resend API key.' },
}

// Emails IAMKit renders, in display order (authentication.PreviewPurposes).
export const EMAIL_PURPOSES: { purpose: string; label: string }[] = [
  { purpose: 'login', label: 'Login code' },
  { purpose: 'password_reset', label: 'Password reset' },
  { purpose: 'email_verification', label: 'Email verification' },
  { purpose: 'invitation', label: 'Invitation' },
  { purpose: 'test', label: 'Test email' },
]
export const purposeLabel = (purpose: string) => EMAIL_PURPOSES.find(p => p.purpose === purpose)?.label ?? purpose

export interface SMTPPreset { id: string; label: string; host: string; port: number; tls: 'starttls' | 'tls'; username?: string; hint?: string }
export const SMTP_PRESETS: SMTPPreset[] = [
  { id: 'google', label: 'Google Workspace / Gmail', host: 'smtp.gmail.com', port: 587, tls: 'starttls', hint: 'Use an app password.' },
  { id: 'microsoft', label: 'Microsoft 365', host: 'smtp.office365.com', port: 587, tls: 'starttls', hint: 'SMTP AUTH must be enabled for the mailbox.' },
  { id: 'ses', label: 'Amazon SES', host: 'email-smtp.us-east-1.amazonaws.com', port: 587, tls: 'starttls', hint: 'Change the region in the host name; use SES SMTP credentials.' },
  { id: 'sendgrid', label: 'SendGrid', host: 'smtp.sendgrid.net', port: 587, tls: 'starttls', username: 'apikey', hint: 'The password is your SendGrid API key.' },
  { id: 'mailgun', label: 'Mailgun', host: 'smtp.mailgun.org', port: 587, tls: 'starttls' },
  { id: 'postmark', label: 'Postmark', host: 'smtp.postmarkapp.com', port: 587, tls: 'starttls', hint: 'Username and password are both your server API token.' },
]

// DeliveryDraft is the delivery form: every provider's fields, of which
// only the chosen provider's are sent.
export interface DeliveryDraft {
  provider: Provider
  webhook_url: string; webhook_token: string
  from_email: string; from_name: string; reply_to: string
  smtp_host: string; smtp_port: string; smtp_tls: 'starttls' | 'tls'; smtp_username: string; smtp_password: string
  api_key: string
  invitation_url: string
}

export function draftFrom(c: DeliveryConfig | null): DeliveryDraft {
  return {
    provider: c?.provider || 'webhook',
    webhook_url: c?.webhook_url ?? '', webhook_token: '',
    from_email: c?.from_email ?? '', from_name: c?.from_name ?? '', reply_to: c?.reply_to ?? '',
    smtp_host: c?.smtp_host ?? '', smtp_port: c?.smtp_port ? String(c.smtp_port) : '587', smtp_tls: c?.smtp_tls || 'starttls',
    smtp_username: c?.smtp_username ?? '', smtp_password: '', api_key: '',
    invitation_url: c?.invitation_url ?? '',
  }
}

// copySettings takes another environment's non-secret settings.
export function copySettings(d: DeliveryDraft, from: DeliveryConfig): DeliveryDraft {
  const next = draftFrom(from)
  return { ...next, webhook_token: d.provider === next.provider ? d.webhook_token : '', smtp_password: '', api_key: '' }
}

// deliveryBody is the PUT /delivery request for the draft: the chosen
// provider's fields only (the server rejects the others). A blank secret
// keeps the stored one.
export function deliveryBody(d: DeliveryDraft): Record<string, unknown> {
  const t = (s: string) => s.trim()
  const invitation_url = t(d.invitation_url)
  if (d.provider === 'webhook') return { provider: 'webhook', webhook_url: t(d.webhook_url), webhook_token: t(d.webhook_token), invitation_url }
  const sender = { from_email: t(d.from_email), from_name: t(d.from_name), reply_to: t(d.reply_to) }
  if (d.provider === 'resend') return { provider: 'resend', ...sender, ...(t(d.api_key) && { api_key: t(d.api_key) }), invitation_url }
  return {
    provider: 'smtp', ...sender,
    smtp_host: t(d.smtp_host), smtp_port: Number(d.smtp_port) || 587, smtp_tls: d.smtp_tls,
    smtp_username: t(d.smtp_username), ...(d.smtp_password && t(d.smtp_username) && { smtp_password: d.smtp_password }),
    invitation_url,
  }
}

// secretKept tells whether the stored secret still applies to the draft: same
// provider and, for SMTP, the same server and account — the server refuses to
// send a stored password anywhere else.
export function secretKept(d: DeliveryDraft, existing: DeliveryConfig | null) {
  if (!existing?.has_secret || existing.provider !== d.provider) return false
  if (d.provider !== 'smtp') return true
  return existing.smtp_host === d.smtp_host.trim().toLowerCase() && existing.smtp_port === (Number(d.smtp_port) || 587) &&
    existing.smtp_tls === d.smtp_tls && existing.smtp_username === d.smtp_username.trim()
}

// needsSecret tells whether the form must ask for a new secret: none is
// stored that applies to the draft.
export function needsSecret(d: DeliveryDraft, existing: DeliveryConfig | null) {
  const kept = secretKept(d, existing)
  if (d.provider === 'resend') return !kept
  if (d.provider === 'smtp') return !!d.smtp_username.trim() && !kept
  return false
}

export function sender(c: Pick<DeliveryConfig, 'from_email' | 'from_name'>) {
  return c.from_name ? `${c.from_name} <${c.from_email}>` : c.from_email
}

// The effective provider: the environment's own, else the global one.
export function effectiveProvider(config: DeliveryConfig | null, status: DeliveryStatus): Provider | '' {
  if (config) return config.provider || 'webhook'
  if (status.source === 'global') return status.provider || 'webhook'
  return ''
}
export const rendered = (p: Provider | '') => p === 'smtp' || p === 'resend'
