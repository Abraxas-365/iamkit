import { createContext, useContext } from 'react'
import type { Claims, Client, Portal } from './session'
import { t } from '@/lib/i18n'

export interface Admin {
  environment: string
  portal: Portal
  client: Client
  claims: Claims
  /** can reports whether the token carries the permission (the server
   * checks it again; this only hides what would be refused). */
  can: (permission: string) => boolean
  /** Set in a setup-link session: the intents the link allows and the
   * organization's name. Setup sessions have no user, sign-out or member UI. */
  setup?: { intents: string[]; organization_name: string }
}

/** OWNER is the pseudo-permission `can` answers for an account holding every
 * organization permission (the org_owner role): who may manage setup links. */
export const OWNER = 'owner'

/** Every organization permission: what the org_owner role holds. */
export const ORG_PERMISSIONS = [
  'iam:org:read', 'iam:org:settings:write', 'iam:org:members:read', 'iam:org:members:write', 'iam:org:users:write',
  'iam:org:roles:read', 'iam:org:roles:assign', 'iam:org:invitations:write', 'iam:org:domains:write', 'iam:org:sso:write',
  'iam:org:audit:read', 'iam:org:resources:read', 'iam:org:resources:write', 'iam:org:log-streams:write',
  'iam:org:api-keys:read', 'iam:org:api-keys:write',
]

export const AdminContext = createContext<Admin | null>(null)

export function useAdmin() {
  const admin = useContext(AdminContext)
  if (!admin) throw new Error(t('useAdmin outside the organization admin portal'))
  return admin
}
