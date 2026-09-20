import { useRef, useState } from 'react'
import { Link, Navigate } from 'react-router-dom'
import { KeyRound } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { message } from '@/lib/utils'
import { request } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card } from '@/components/ui/card'
import { ErrorState } from '@/components/library/patterns'

export default function SetupPage() {
  const auth = useAuth()
  const [step, setStep] = useState<'key' | 'password' | 'done'>('key')
  const [apiKey, setApiKey] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const pending = useRef(false)

  if (auth.loading) return <p role="status" className="p-8">Loading session…</p>
  if (auth.principal) return <Navigate to="/" replace />

  return <main className="flex min-h-dvh items-center justify-center bg-sidebar p-6"><Card className="w-full max-w-sm space-y-6 p-8">
    <div className="flex size-10 items-center justify-center rounded-lg bg-primary text-primary-foreground"><KeyRound /></div>
    <div>
      <h1 className="font-mono text-xl font-bold tracking-tight">Set up your account</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        {step === 'key' && 'Paste the management API key you received from your workspace owner.'}
        {step === 'password' && 'Set a password to sign in to the IAMKit console.'}
        {step === 'done' && success}
      </p>
    </div>

    {step === 'key' && <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const key = String(new FormData(event.currentTarget).get('api_key') ?? '').trim()
      if (!key.startsWith('ik_mgmt_')) { setError('API key must start with ik_mgmt_'); return }
      pending.current = true; setBusy(true); setError('')
      try {
        // Verify the key is valid by calling /me with it
        await request('/me', { headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json', 'X-IAMKit-Console': '1' } })
        setApiKey(key)
        setStep('password')
      } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label htmlFor="api-key">Management API key</label>
        <Input id="api-key" name="api_key" type="password" required autoComplete="off" placeholder="ik_mgmt_..." disabled={busy} />
      </div>
      {error && <ErrorState error={error} />}
      <Button className="w-full" type="submit" disabled={busy}>{busy ? 'Verifying…' : 'Continue'}</Button>
      <p className="text-center text-xs text-muted-foreground">Already have a password? <Link to="/login" className="text-primary underline">Sign in</Link></p>
    </form>}

    {step === 'password' && <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const data = new FormData(event.currentTarget)
      const password = String(data.get('password') ?? '')
      const confirm = String(data.get('confirm') ?? '')
      if (password !== confirm) { setError('Passwords do not match.'); return }
      const bytes = new TextEncoder().encode(password).length
      if (bytes < 12 || bytes > 72) { setError('Password must be 12–72 characters long.'); return }
      pending.current = true; setBusy(true); setError('')
      try {
        await request('/password', {
          method: 'POST',
          body: JSON.stringify({ password }),
          headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json', 'X-IAMKit-Console': '1' },
        })
        setSuccess('Password set successfully! You can now sign in with your email and password.')
        setStep('done')
      } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label htmlFor="new-password">New password</label>
        <Input id="new-password" name="password" type="password" required autoComplete="new-password" disabled={busy} />
      </div>
      <div className="space-y-1.5">
        <label htmlFor="confirm-password">Confirm password</label>
        <Input id="confirm-password" name="confirm" type="password" required autoComplete="new-password" disabled={busy} />
      </div>
      <p className="text-xs text-muted-foreground">Use a unique password between 12 and 72 characters long.</p>
      {error && <ErrorState error={error} />}
      <Button className="w-full" type="submit" disabled={busy}>{busy ? 'Setting password…' : 'Set password'}</Button>
    </form>}

    {step === 'done' && <div className="space-y-4">
      <Link to="/login"><Button className="w-full">Go to sign in</Button></Link>
    </div>}
  </Card></main>
}
