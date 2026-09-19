import { Link, Navigate } from 'react-router-dom'
import { Shield } from 'lucide-react'
import { useRef, useState } from 'react'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { ErrorState } from '@/components/library/patterns'
export default function LoginPage() {
  const auth = useAuth()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  if (auth.loading) return <p role="status" className="p-8">Loading session…</p>
  if (auth.principal) return <Navigate to="/" replace />
  return <main className="flex min-h-dvh items-center justify-center bg-sidebar p-6"><Card className="w-full max-w-sm space-y-6 p-8">
    <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground"><Shield /></div>
    <div><h1 className="font-mono text-xl font-bold tracking-tight">Sign in to IAMKit</h1><p className="mt-2 text-sm text-muted-foreground">Manage your identities, access, and applications.</p></div>
    <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const data = new FormData(event.currentTarget)
      pending.current = true; setBusy(true); setError('')
      try { await auth.login(String(data.get('email')), String(data.get('password'))) } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5"><label htmlFor="email">Operator email</label><Input id="email" name="email" type="email" required autoComplete="username" disabled={busy} /></div>
      <div className="space-y-1.5"><label htmlFor="password">Password</label><Input id="password" name="password" type="password" required autoComplete="current-password" disabled={busy} /></div>
      {(error || auth.error) && <ErrorState error={error || auth.error} />}
      <Button className="w-full" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
    </form>
    <p className="text-xs text-muted-foreground">New operator? <Link to="/setup" className="text-primary underline">Set up your account</Link> with your API key.</p>
  </Card></main>
}
