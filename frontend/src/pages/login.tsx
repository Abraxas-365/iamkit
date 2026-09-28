import { Link, Navigate, useSearchParams } from 'react-router-dom'
import { KeyRound } from 'lucide-react'
import { Logo } from '@/components/brand/logo'
import { useRef, useState } from 'react'
import { useAuth } from '@/lib/auth'
import type { SSOProvider } from '@/lib/auth'
import { ApiError } from '@/lib/api'
import { cn, message } from '@/lib/utils'
import { Button, buttonVariants } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { ErrorState } from '@/components/library/patterns'

// Reasons the SSO callback sends back as /login?sso_error=… (mgmthttp/sso.go).
const ssoErrors: Record<string, string> = {
  expired: 'The sign-in expired or was started in another browser. Please try again.',
  not_authorized: 'This account cannot sign in to the console. Ask a workspace owner to invite your work email.',
  provider_unavailable: 'The identity provider could not be reached. Try again later.',
  cancelled: 'Sign-in was cancelled at the identity provider.',
  failed: 'Single sign-on failed. Please try again.',
}

function GoogleIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true" className="size-4"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.27-4.74 3.27-8.1z" /><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84A11 11 0 0 0 12 23z" /><path fill="#FBBC05" d="M5.84 14.1a6.6 6.6 0 0 1 0-4.2V7.06H2.18a11 11 0 0 0 0 9.88l3.66-2.84z" /><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15A10.55 10.55 0 0 0 12 1 11 11 0 0 0 2.18 7.06l3.66 2.84C6.71 7.31 9.14 5.38 12 5.38z" /></svg>
}
function MicrosoftIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true" className="size-4"><path fill="#F25022" d="M2 2h9.5v9.5H2z" /><path fill="#7FBA00" d="M12.5 2H22v9.5h-9.5z" /><path fill="#00A4EF" d="M2 12.5h9.5V22H2z" /><path fill="#FFB900" d="M12.5 12.5H22V22h-9.5z" /></svg>
}
function ProviderButton({ provider }: { provider: SSOProvider }) {
  const icon = provider.type === 'google' ? <GoogleIcon /> : provider.type === 'microsoft' ? <MicrosoftIcon /> : <KeyRound className="size-4" aria-hidden="true" />
  // A full-page navigation: the server redirects to the provider and sets a binding cookie.
  return <a href={`/management/v1/sso/${encodeURIComponent(provider.id)}/start`} className={cn(buttonVariants({ variant: 'outline' }), 'w-full gap-2')}>{icon}Continue with {provider.name}</a>
}

export default function LoginPage() {
  const auth = useAuth()
  const [params] = useSearchParams()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  // Credentials that matched a password someone else chose (bootstrap): the
  // operator picks their own before the session starts.
  const [change, setChange] = useState<{ email: string; password: string } | null>(null)
  const pending = useRef(false)
  if (auth.loading || !auth.options) return <p role="status" className="p-8">Loading session…</p>
  if (auth.principal) return <Navigate to="/" replace />
  const { password, providers } = auth.options
  const ssoError = params.get('sso_error')
  const ssoMessage = ssoError ? ssoErrors[ssoError] ?? ssoErrors.failed : ''
  if (change) return <main className="flex min-h-dvh items-center justify-center bg-sidebar p-6"><Card className="w-full max-w-sm space-y-6 p-8">
    <Logo className="h-9 self-start" />
    <div><h1 className="font-mono text-xl font-bold tracking-tight">Choose a new password</h1><p className="mt-2 text-sm text-muted-foreground">Your password was set for you. Choose your own to finish signing in as {change.email}.</p></div>
    <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const data = new FormData(event.currentTarget)
      const next = String(data.get('new_password'))
      if (next !== data.get('confirm')) { setError('Passwords do not match.'); return }
      const bytes = new TextEncoder().encode(next).length
      if (bytes < 12 || bytes > 72) { setError('Password must be 12–72 characters long.'); return }
      if (next === change.password) { setError('Choose a password different from the current one.'); return }
      pending.current = true; setBusy(true); setError('')
      try { await auth.login(change.email, change.password, next) } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <input type="text" name="email" autoComplete="username" value={change.email} readOnly hidden />
      <div className="space-y-1.5"><label htmlFor="new-password">New password</label><Input id="new-password" name="new_password" type="password" required autoComplete="new-password" disabled={busy} /></div>
      <div className="space-y-1.5"><label htmlFor="confirm-password">Confirm password</label><Input id="confirm-password" name="confirm" type="password" required autoComplete="new-password" disabled={busy} /></div>
      <p className="text-xs text-muted-foreground">Use a unique password between 12 and 72 characters long.</p>
      {error && <ErrorState error={error} />}
      <div className="flex gap-2"><Button type="button" variant="outline" disabled={busy} onClick={() => { setChange(null); setError('') }}>Back</Button><Button className="flex-1" type="submit" disabled={busy}>{busy ? 'Saving…' : 'Set password and sign in'}</Button></div>
    </form>
  </Card></main>
  return <main className="flex min-h-dvh items-center justify-center bg-sidebar p-6"><Card className="w-full max-w-sm space-y-6 p-8">
    <Logo className="h-9 self-start" />
    <div><h1 className="font-mono text-xl font-bold tracking-tight">Sign in to IAMKit</h1><p className="mt-2 text-sm text-muted-foreground">Manage your identities, access, and applications.</p></div>
    {ssoMessage && <ErrorState error={ssoMessage} />}
    {providers.length > 0 && <div className="space-y-2">{providers.map(p => <ProviderButton key={p.id} provider={p} />)}</div>}
    {providers.length > 0 && password && <div className="flex items-center gap-3 text-xs text-muted-foreground" role="separator" aria-label="or"><span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" /></div>}
    {password && <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const data = new FormData(event.currentTarget)
      const email = String(data.get('email')), current = String(data.get('password'))
      pending.current = true; setBusy(true); setError('')
      try { await auth.login(email, current) } catch (e) {
        if (e instanceof ApiError && e.code === 'PASSWORD_CHANGE_REQUIRED') setChange({ email, password: current })
        else setError(message(e))
      } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5"><label htmlFor="email">Operator email</label><Input id="email" name="email" type="email" required autoComplete="username" disabled={busy} /></div>
      <div className="space-y-1.5"><label htmlFor="password">Password</label><Input id="password" name="password" type="password" required autoComplete="current-password" disabled={busy} /></div>
      {(error || auth.error) && <ErrorState error={error || auth.error} />}
      <Button className="w-full" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</Button>
    </form>}
    {!password && auth.error && <ErrorState error={auth.error} />}
    {password
      ? <p className="text-xs text-muted-foreground">New operator? <Link to="/setup" className="text-primary underline">Set up your account</Link> with your API key.</p>
      : <p className="text-xs text-muted-foreground">New operator? Ask a workspace owner to invite your work email, then sign in with single sign-on.</p>}
  </Card></main>
}
