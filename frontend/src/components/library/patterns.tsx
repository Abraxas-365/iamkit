import type { ReactNode } from 'react'
import { useId, useRef, useState } from 'react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SearchSelect } from '@/components/ui/search-select'
import { TagInput } from '@/components/ui/tag-input'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { message } from '@/lib/utils'

export { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
export function ErrorState({ error, retry }: { error: string; retry?: () => void }) {
  return <div role="alert" className="space-y-3 rounded-lg border border-destructive/30 p-4"><p className="text-sm text-destructive">{error}</p>{retry && <Button variant="outline" onClick={retry}>Try again</Button>}</div>
}
export interface Field {
  name: string; label: string; type?: 'text' | 'email' | 'password' | 'list' | 'tags' | 'checkbox' | 'select' | 'dropdown';
  optional?: boolean; value?: string | boolean; hint?: string;
  /** For type='tags': pre-split array of values */
  tags?: string[];
  /** For type='tags': auto-prefix typed values */
  prefix?: string;
  /** For type='select': API path to fetch options */
  selectPath?: string;
  /** For type='select': map each API item to { id, label } */
  selectMap?: (item: Record<string, unknown>) => { id: string; label: string };
  /** For type='dropdown': static options */
  options?: { label: string; value: string }[];
}
export function FormDialog({ title, description, fields, submit, onClose }: { title: string; description: string; fields: Field[]; submit: (data: Record<string, string | boolean>) => Promise<void>; onClose: () => void }) {
  const id = useId()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}><DialogContent>
    <DialogTitle className="pr-6 text-base font-semibold">{title}</DialogTitle><DialogDescription className="text-muted-foreground">{description}</DialogDescription>
    <form className="space-y-4" onSubmit={async event => {
      event.preventDefault(); if (pending.current) return
      const form = new FormData(event.currentTarget)
      const data = Object.fromEntries(fields.map(f => [f.name, f.type === 'checkbox' ? form.has(f.name) : f.type === 'password' ? String(form.get(f.name) ?? '') : String(form.get(f.name) ?? '').trim()]))
      pending.current = true; setBusy(true); setError('')
      try { await submit(data); toast.success('Saved successfully'); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      {fields.map(field => <div className="space-y-1.5" key={field.name}>
        <label className="text-sm font-medium" htmlFor={`${id}-${field.name}`}>{field.label}</label>
        {field.type === 'checkbox' ? <input className="ml-3 accent-primary" id={`${id}-${field.name}`} name={field.name} type="checkbox" defaultChecked={field.value === true} disabled={busy} /> :
          field.type === 'dropdown' && field.options ? <select id={`${id}-${field.name}`} name={field.name} className="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" defaultValue={String(field.value ?? field.options[0]?.value ?? '')} disabled={busy}>{field.options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select> :
          field.type === 'select' && field.selectPath && field.selectMap ? <SearchSelect id={`${id}-${field.name}`} name={field.name} path={field.selectPath} mapItem={field.selectMap} defaultValue={String(field.value ?? '')} required={!field.optional} disabled={busy} placeholder={`Search ${field.label.toLowerCase()}…`} /> :
          field.type === 'tags' ? <TagInput id={`${id}-${field.name}`} name={field.name} defaultValue={field.tags ?? []} disabled={busy} placeholder="Type and press Enter…" prefix={field.prefix} /> :
          <Input id={`${id}-${field.name}`} name={field.name} type={field.type === 'list' ? 'text' : field.type ?? 'text'} defaultValue={String(field.value ?? '')} required={!field.optional} disabled={busy} autoComplete={field.type === 'password' ? 'new-password' : 'off'} />}
        {field.hint && <p className="text-xs text-muted-foreground">{field.hint}</p>}
      </div>)}
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Save'}</Button></div>
    </form>
  </DialogContent></Dialog>
}
export function ConfirmDialog({ title, description, confirm, onClose }: { title: string; description: string; confirm: () => Promise<void>; onClose: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}><DialogContent>
    <DialogTitle className="text-base font-semibold">{title}</DialogTitle><DialogDescription className="text-muted-foreground">{description}</DialogDescription>
    {error && <ErrorState error={error} />}
    <div className="flex justify-end gap-2"><Button variant="outline" disabled={busy} onClick={onClose}>Cancel</Button><Button variant="destructive" disabled={busy} onClick={async () => { if (pending.current) return; pending.current = true; setBusy(true); try { await confirm(); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) } }}>{busy ? 'Working…' : 'Confirm'}</Button></div>
  </DialogContent></Dialog>
}
export function DataTable({ columns, rows, loading, error, retry }: { columns: string[]; rows: ReactNode[][]; loading: boolean; error: string; retry: () => void }) {
  if (loading) return <div role="status" className="space-y-3 py-4">{[1, 2, 3].map(i => <Skeleton key={i} className="h-10" />)}<span className="sr-only">Loading data…</span></div>
  if (error) return <ErrorState error={error} retry={retry} />
  if (!rows.length) return <div className="rounded-lg border border-dashed py-16 text-center text-sm text-muted-foreground">No results found.</div>
  return <div className="overflow-hidden rounded-lg border bg-card"><Table><TableHeader><TableRow>{columns.map(c => <TableHead key={c}>{c}</TableHead>)}</TableRow></TableHeader><TableBody>{rows.map((row, i) => <TableRow key={i}>{row.map((cell, j) => <TableCell key={j}>{cell}</TableCell>)}</TableRow>)}</TableBody></Table></div>
}
export function Status({ active }: { active: boolean }) { return <Badge variant="secondary" className={active ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}>{active ? 'Active' : 'Inactive'}</Badge> }
export function ID({ value }: { value: string }) { return <span className="font-mono text-xs text-muted-foreground" title={value}>{value}</span> }
export function splitList(value: string | boolean) { return String(value).split(',').map(v => v.trim()).filter(Boolean) }
