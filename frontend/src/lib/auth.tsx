import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { api, ApiError } from './api'
import { message } from './utils'
export interface Principal { operator_id: string; workspace_id: string; role: 'owner' | 'admin' | 'viewer'; method?: 'password' | 'sso' | 'key'; authenticated_at?: string }
export interface SSOProvider { id: string; name: string; type: 'oidc' | 'google' | 'microsoft' }
/** How operators sign in to this deployment (IAMKIT_OPERATOR_SSO_*, IAMKIT_OPERATOR_PASSWORD_LOGIN). */
export interface LoginOptions { password: boolean; providers: SSOProvider[] }
interface Auth { principal: Principal | null; options: LoginOptions | null; loading: boolean; error: string; reload: () => Promise<void>; login: (email: string, password: string, newPassword?: string) => Promise<void>; logout: () => Promise<void> }
const Context = createContext<Auth | null>(null)
// Deployments without the endpoint, or a failed request, keep the password form.
const passwordOnly: LoginOptions = { password: true, providers: [] }
async function loadOptions(): Promise<LoginOptions> {
  try {
    const response = await fetch('/management/v1/login-options', { credentials: 'same-origin', headers: { 'X-IAMKit-Console': '1' } })
    if (!response.ok) return passwordOnly
    const body = await response.json() as Partial<LoginOptions> | null
    return { password: body?.password !== false, providers: Array.isArray(body?.providers) ? body.providers : [] }
  } catch { return passwordOnly }
}
export function AuthProvider({ children }: { children: ReactNode }) {
  const [principal, setPrincipal] = useState<Principal | null>(null)
  const [options, setOptions] = useState<LoginOptions | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const generation = useRef(0)
  const reload = useCallback(async () => {
    const current = ++generation.current
    setLoading(true); setError('')
    try { const p = await api.get<Principal>('/me'); if (current === generation.current) setPrincipal(p) }
    catch (e) { if (current === generation.current) { setPrincipal(null); if (!(e instanceof ApiError && e.status === 401)) setError(message(e)) } }
    finally { if (current === generation.current) setLoading(false) }
  }, [])
  useEffect(() => {
    let live = true
    const expired = () => { ++generation.current; setPrincipal(null); setLoading(false) }
    window.addEventListener('session-expired', expired)
    void reload()
    void loadOptions().then(o => { if (live) setOptions(o) })
    return () => { live = false; ++generation.current; window.removeEventListener('session-expired', expired) }
  }, [reload])
  async function login(email: string, password: string, newPassword?: string) {
    // new_password replaces a password that must change (PASSWORD_CHANGE_REQUIRED).
    await api.post<Principal>('/login', newPassword ? { email, password, new_password: newPassword } : { email, password })
    // Verify the browser accepted the Secure cookie, rather than trusting the login response.
    const p = await api.get<Principal>('/me')
    ++generation.current; setPrincipal(p); setError('')
  }
  async function logout() { await api.delete('/sessions/current'); ++generation.current; setPrincipal(null) }
  return <Context.Provider value={{ principal, options, loading, error, reload, login, logout }}>{children}</Context.Provider>
}
export function useAuth() { const value = useContext(Context); if (!value) throw new Error('AuthProvider required'); return value }
