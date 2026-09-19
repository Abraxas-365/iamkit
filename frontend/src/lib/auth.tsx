import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { api, ApiError } from './api'
import { message } from './utils'
export interface Principal { operator_id: string; workspace_id: string; role: 'owner' | 'admin' | 'viewer' }
interface Auth { principal: Principal | null; loading: boolean; error: string; reload: () => Promise<void>; login: (email: string, password: string) => Promise<void>; logout: () => Promise<void> }
const Context = createContext<Auth | null>(null)
export function AuthProvider({ children }: { children: ReactNode }) {
  const [principal, setPrincipal] = useState<Principal | null>(null)
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
    const expired = () => { ++generation.current; setPrincipal(null); setLoading(false) }
    window.addEventListener('session-expired', expired)
    void reload()
    return () => { ++generation.current; window.removeEventListener('session-expired', expired) }
  }, [reload])
  async function login(email: string, password: string) {
    await api.post<Principal>('/login', { email, password })
    // Verify the browser accepted the Secure cookie, rather than trusting the login response.
    const p = await api.get<Principal>('/me')
    ++generation.current; setPrincipal(p); setError('')
  }
  async function logout() { await api.delete('/sessions/current'); ++generation.current; setPrincipal(null) }
  return <Context.Provider value={{ principal, loading, error, reload, login, logout }}>{children}</Context.Provider>
}
export function useAuth() { const value = useContext(Context); if (!value) throw new Error('AuthProvider required'); return value }
