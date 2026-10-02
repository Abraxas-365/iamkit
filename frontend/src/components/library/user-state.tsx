import { Badge } from '@/components/ui/badge'
import { t } from '@/lib/i18n'

/** Derived user states returned by the API (`state`). */
export const userStates = [
  ['active', t('Active'), t('Can sign in.')],
  ['initial', t('Never signed in'), t('Created, invited or provisioned and not used yet.')],
  ['inactive', t('Inactive'), t('No active membership in an active organization, so no sign-in can succeed.')],
  ['locked', t('Locked'), t('Too many wrong passwords; password sign-in is refused for now.')],
  ['suspended', t('Suspended'), t('Deactivated by an administrator; nothing signs in.')],
] as const

const tone: Record<string, string> = {
  active: 'bg-success/10 text-success',
  initial: 'bg-primary/10 text-primary',
  inactive: 'bg-muted text-muted-foreground',
  locked: 'bg-destructive/10 text-destructive',
  suspended: 'bg-muted text-muted-foreground',
}

/** UserState shows a user's derived state; older servers without `state`
 * fall back to active/suspended. */
export function UserState({ state, active }: { state?: string; active?: boolean }) {
  const value = state || (active ? 'active' : 'suspended')
  const entry = userStates.find(s => s[0] === value)
  return <Badge variant="secondary" title={entry?.[2]} className={tone[value] ?? tone.inactive}>{entry?.[1] ?? value}</Badge>
}
