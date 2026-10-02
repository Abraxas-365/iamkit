import { useId, useRef, useState } from 'react'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { api } from '@/lib/api'
import { message } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { ConfirmDialog, DetailSection, ErrorState, FormDialog } from '@/components/library/patterns'
import { t } from '@/lib/i18n'

/** Metadata limits enforced by the server (identity.ValidateMetadata). */
export const metadataKey = /^[a-zA-Z0-9_.-]{1,64}$/

/** parseValue reads a metadata value: JSON when it parses, else a string. */
export function parseValue(raw: string): unknown {
  try { return JSON.parse(raw) } catch { return raw }
}

function show(value: unknown) { return typeof value === 'string' ? value : JSON.stringify(value) }

/** MetadataEditor lists metadata keys and changes one at a time through
 * PUT/DELETE {path}/metadata/:key (audited per key). */
export function MetadataEditor({ path, metadata, canWrite, reload, description }: { path: string; metadata: Record<string, unknown> | null | undefined; canWrite: boolean; reload: () => void; description?: string }) {
  const [editing, setEditing] = useState<string | null>(null) // '' = new key
  const [removing, setRemoving] = useState('')
  const entries = Object.entries(metadata ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return <DetailSection title={t('Metadata')} description={description ?? t('Free-form operator data: up to 64 keys, 4 KiB per value, 32 KiB in total. Every change is audited.')}
    actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing('')}><Plus /> {t('Add key')}</Button>}>
    {entries.length === 0 ? <p className="text-sm text-muted-foreground">{t('No metadata.')}</p> :
      <dl className="divide-y rounded-lg border text-sm">{entries.map(([key, value]) => <div key={key} className="flex items-start gap-3 px-3 py-2">
        <dt className="w-40 shrink-0 break-all font-mono text-xs font-medium">{key}</dt>
        <dd className="min-w-0 flex-1 break-all font-mono text-xs text-muted-foreground">{show(value)}</dd>
        {canWrite && <span className="flex shrink-0 gap-1">
          <Button variant="ghost" size="icon-sm" aria-label={t('Edit {{key}}', { key })} onClick={() => setEditing(key)}><Pencil /></Button>
          <Button variant="ghost" size="icon-sm" aria-label={t('Delete {{key}}', { key })} onClick={() => setRemoving(key)}><Trash2 /></Button>
        </span>}
      </div>)}</dl>}
    {editing !== null && <FormDialog title={editing ? t('Edit {{editing}}', { editing }) : t('Add metadata key')} description={t('The value is JSON (an object, number, true…) or plain text.')} fields={[
      ...(editing ? [] : [{ name: 'key', label: t('Key'), hint: t('Letters, digits, ".", "_" or "-"; up to 64 characters.') }]),
      { name: 'value', label: t('Value'), value: editing ? show(metadata?.[editing]) : '' },
    ]} onClose={() => setEditing(null)} submit={async values => {
      const key = editing || String(values.key)
      if (!metadataKey.test(key)) throw new Error(t('Key must be 1-64 letters, digits, ".", "_" or "-"'))
      await api.put(`${path}/metadata/${encodeURIComponent(key)}`, parseValue(String(values.value)))
      reload()
    }} />}
    {removing && <ConfirmDialog title={t('Delete {{removing}}?', { removing })} description={t('The key is removed from the metadata.')} confirmLabel={t('Delete')} onClose={() => setRemoving('')} confirm={async () => {
      await api.delete(`${path}/metadata/${encodeURIComponent(removing)}`); toast.success(t('Metadata key deleted')); reload()
    }} />}
  </DetailSection>
}

/** JSONDialog edits one JSON object in a textarea; submit gets it parsed. */
export function JSONDialog({ title, description, label, value, submit, onClose, success = t('Saved') }: { title: string; description: string; label: string; value: unknown; submit: (value: Record<string, unknown>) => Promise<void>; onClose: () => void; success?: string }) {
  const id = useId()
  const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}><DialogContent className="sm:max-w-2xl">
    <DialogTitle className="pr-6 text-base font-semibold">{title}</DialogTitle><DialogDescription className="text-muted-foreground">{description}</DialogDescription>
    <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      let parsed: unknown
      try { parsed = JSON.parse(text) } catch { setError(t('{{label}} must be valid JSON', { label })); return }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) { setError(t('{{label}} must be a JSON object', { label })); return }
      pending.current = true; setBusy(true); setError('')
      try { await submit(parsed as Record<string, unknown>); if (success) toast.success(success); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      <div className="space-y-1.5">
        <label className="text-sm font-medium" htmlFor={id}>{label}</label>
        <textarea id={id} className="min-h-64 w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs" spellCheck={false} value={text} disabled={busy} onChange={e => setText(e.target.value)} />
      </div>
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>{t('Cancel')}</Button><Button type="submit" disabled={busy}>{busy ? t('Saving…') : t('Save')}</Button></div>
    </form>
  </DialogContent></Dialog>
}

/** ProfileAttributes shows a user's profile (the attributes the user schema
 * describes) and replaces it through PATCH {path}/profile. */
export function ProfileAttributes({ path, profile, canWrite, reload }: { path: string; profile: Record<string, unknown> | null | undefined; canWrite: boolean; reload: () => void }) {
  const [editing, setEditing] = useState(false)
  const entries = Object.entries(profile ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return <DetailSection title={t('Profile attributes')} description={t('Attributes checked against the environment\'s user schema; annotated ones reach ID tokens or the user\'s self-service profile.')}
    actions={canWrite && <Button variant="outline" size="sm" onClick={() => setEditing(true)}><Pencil /> {t('Edit')}</Button>}>
    {entries.length === 0 ? <p className="text-sm text-muted-foreground">{t('No attributes.')}</p> :
      <dl className="divide-y rounded-lg border text-sm">{entries.map(([key, value]) => <div key={key} className="flex items-start gap-3 px-3 py-2">
        <dt className="w-40 shrink-0 break-all font-mono text-xs font-medium">{key}</dt>
        <dd className="min-w-0 flex-1 break-all font-mono text-xs text-muted-foreground">{show(value)}</dd>
      </div>)}</dl>}
    {editing && <JSONDialog title={t('Edit profile attributes')} description={t('The whole profile as a JSON object. It must match the user schema when one is saved.')} label={t('Profile')} value={profile} onClose={() => setEditing(false)} submit={async next => {
      // PATCH merges: send removed keys as null.
      const patch: Record<string, unknown> = { ...next }
      for (const key of Object.keys(profile ?? {})) if (!(key in next)) patch[key] = null
      await api.patch(`${path}/profile`, patch); reload()
    }} />}
  </DetailSection>
}
