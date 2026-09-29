/** Second-factor kinds (identity.FactorKinds) and how the console names them. */
export const FACTORS = [
  { kind: 'totp', label: 'Authenticator app', hint: 'Time-based codes (TOTP) from an app such as Google Authenticator or 1Password.' },
  { kind: 'webauthn', label: 'Security keys and passkeys', hint: 'WebAuthn: hardware keys, Touch ID, Windows Hello. Phishing-resistant.' },
  { kind: 'sms', label: 'Code by text message (SMS)', hint: 'A code texted to a confirmed phone number. Needs an SMS provider under Notifications.' },
  { kind: 'email', label: 'Code by email', hint: 'A code emailed to the account address. Not accepted after an email-code sign-in (same inbox).' },
] as const

export type FactorKind = typeof FACTORS[number]['kind']

/** toggleFactor adds or removes kind, keeping the catalog order. */
export function toggleFactor(list: string[], kind: string, on: boolean): string[] {
  const next = new Set(list)
  if (on) next.add(kind); else next.delete(kind)
  return FACTORS.map(f => f.kind).filter(k => next.has(k))
}
