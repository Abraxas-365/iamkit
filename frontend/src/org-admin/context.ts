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
}

export const AdminContext = createContext<Admin | null>(null)

export function useAdmin() {
  const admin = useContext(AdminContext)
  if (!admin) throw new Error(t('useAdmin outside the organization admin portal'))
  return admin
}
