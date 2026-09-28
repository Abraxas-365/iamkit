import type { ReactNode } from 'react'
import { useId, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, Check, Copy } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { SearchSelect } from '@/components/ui/search-select'
import { TagInput } from '@/components/ui/tag-input'
import { Dialog, DialogContent, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { cn, message } from '@/lib/utils'

export { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
export function ErrorState({ error, retry }: { error: string; retry?: () => void }) {
  return <div role="alert" className="space-y-3 rounded-lg border border-destructive/30 p-4"><p className="text-sm text-destructive">{error}</p>{retry && <Button variant="outline" onClick={retry}>Try again</Button>}</div>
}
export interface Field {
  name: string; label: string; type?: 'text' | 'email' | 'password' | 'list' | 'tags' | 'checkbox' | 'select' | 'dropdown' | 'radio';
  optional?: boolean; value?: string | boolean; hint?: string;
  /** For type='tags': pre-split array of values */
  tags?: string[];
  /** For type='tags': auto-prefix typed values */
  prefix?: string;
  /** For type='select': API path to fetch options */
  selectPath?: string;
  /** For type='select': map each API item to { id, label } */
  selectMap?: (item: Record<string, unknown>) => { id: string; label: string };
  /** For type='dropdown' and 'radio': static options (radio shows descriptions) */
  options?: Option[];
}
export interface Option { label: string; value: string; description?: string }
export const selectClass = 'h-8 w-full rounded-lg border border-input bg-transparent px-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50 dark:bg-input/30'

/** SwitchField is a labelled on/off setting: text on the left, switch on
 * the right. Submits `name=on` when checked, like a checkbox. */
export function SwitchField({ id, name, label, hint, disabled, checked, defaultChecked, onCheckedChange }: { id?: string; name?: string; label: string; hint?: ReactNode; disabled?: boolean; checked?: boolean; defaultChecked?: boolean; onCheckedChange?: (checked: boolean) => void }) {
  const fallback = useId()
  const control = id ?? fallback
  return <div className="flex items-start justify-between gap-4 rounded-lg border p-3">
    <div className="space-y-0.5">
      <label htmlFor={control} className="text-sm font-medium">{label}</label>
      {hint && <p id={`${control}-hint`} className="text-xs text-muted-foreground">{hint}</p>}
    </div>
    <Switch id={control} name={name} value="on" checked={checked} defaultChecked={defaultChecked} onCheckedChange={onCheckedChange} disabled={disabled} aria-describedby={hint ? `${control}-hint` : undefined} className="mt-0.5" />
  </div>
}

/** RadioCards picks one of a few options, each with a short explanation. */
export function RadioCards({ name, label, hint, options, value, defaultValue, onChange, disabled }: { name: string; label: string; hint?: ReactNode; options: Option[]; value?: string; defaultValue?: string; onChange?: (value: string) => void; disabled?: boolean }) {
  return <fieldset className="space-y-1.5" disabled={disabled}>
    <legend className="mb-1.5 text-sm font-medium">{label}</legend>
    <div className="grid gap-2 sm:grid-cols-2">
      {options.map(o => <label key={o.value} className="flex cursor-pointer items-start gap-2.5 rounded-lg border p-3 transition-colors hover:bg-muted/50 has-checked:border-primary has-checked:bg-primary/5 has-disabled:cursor-not-allowed has-disabled:opacity-60">
        <input type="radio" name={name} value={o.value} className="mt-0.5 accent-primary" checked={value === undefined ? undefined : value === o.value} defaultChecked={value === undefined ? defaultValue === o.value : undefined} onChange={() => onChange?.(o.value)} />
        <span className="space-y-0.5"><span className="block text-sm font-medium">{o.label}</span>{o.description && <span className="block text-xs text-muted-foreground">{o.description}</span>}</span>
      </label>)}
    </div>
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </fieldset>
}

export function FormDialog({ title, description, fields, submit, onClose, success = 'Saved', submitLabel = 'Save' }: { title: string; description: string; fields: Field[]; submit: (data: Record<string, string | boolean>) => Promise<void>; onClose: () => void; success?: string; submitLabel?: string }) {
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
      try { await submit(data); if (success) toast.success(success); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) }
    }}>
      {fields.map(field => field.type === 'checkbox' ? <SwitchField key={field.name} id={`${id}-${field.name}`} name={field.name} label={field.label} hint={field.hint} defaultChecked={field.value === true} disabled={busy} /> :
        field.type === 'radio' && field.options ? <RadioCards key={field.name} name={field.name} label={field.label} hint={field.hint} options={field.options} defaultValue={String(field.value ?? field.options[0]?.value ?? '')} disabled={busy} /> :
        <div className="space-y-1.5" key={field.name}>
        <label className="text-sm font-medium" htmlFor={`${id}-${field.name}`}>{field.label}{field.optional && <span className="ml-1 font-normal text-muted-foreground">(optional)</span>}</label>
        {field.type === 'dropdown' && field.options ? <select id={`${id}-${field.name}`} name={field.name} className={selectClass} defaultValue={String(field.value ?? field.options[0]?.value ?? '')} disabled={busy}>{field.options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}</select> :
          field.type === 'select' && field.selectPath && field.selectMap ? <SearchSelect id={`${id}-${field.name}`} name={field.name} path={field.selectPath} mapItem={field.selectMap} defaultValue={String(field.value ?? '')} required={!field.optional} disabled={busy} placeholder={`Search ${field.label.toLowerCase()}…`} /> :
          field.type === 'tags' ? <TagInput id={`${id}-${field.name}`} name={field.name} defaultValue={field.tags ?? []} disabled={busy} placeholder="Type and press Enter…" prefix={field.prefix} /> :
          <Input id={`${id}-${field.name}`} name={field.name} type={field.type === 'list' ? 'text' : field.type ?? 'text'} defaultValue={String(field.value ?? '')} required={!field.optional} disabled={busy} autoComplete={field.type === 'password' ? 'new-password' : 'off'} />}
        {field.hint && <p className="text-xs text-muted-foreground">{field.hint}</p>}
      </div>)}
      {error && <ErrorState error={error} />}
      <div className="flex justify-end gap-2 border-t pt-4"><Button type="button" variant="outline" disabled={busy} onClick={onClose}>Cancel</Button><Button type="submit" disabled={busy}>{busy ? 'Saving…' : submitLabel}</Button></div>
    </form>
  </DialogContent></Dialog>
}
export function ConfirmDialog({ title, description, confirm, onClose, confirmLabel = 'Confirm', confirmationText }: { title: string; description: string; confirm: () => Promise<void>; onClose: () => void; confirmLabel?: string; confirmationText?: string }) {
  const id = useId()
  const [confirmation, setConfirmation] = useState('')
  const confirmed = confirmationText === undefined || confirmation === confirmationText
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const pending = useRef(false)
  return <Dialog open onOpenChange={open => { if (!open && !pending.current) onClose() }}><DialogContent>
    <DialogTitle className="text-base font-semibold">{title}</DialogTitle><DialogDescription className="text-muted-foreground">{description}</DialogDescription>
    {confirmationText !== undefined && <div className="space-y-2">
      <label htmlFor={id} className="text-sm">Type <strong className="break-all">{confirmationText}</strong> to confirm</label>
      <Input id={id} value={confirmation} onChange={e => setConfirmation(e.target.value)} disabled={busy} autoComplete="off" spellCheck={false} />
    </div>}
    {error && <ErrorState error={error} />}
    <div className="flex justify-end gap-2"><Button variant="outline" disabled={busy} onClick={onClose}>Cancel</Button><Button variant="destructive" disabled={busy || !confirmed} onClick={async () => { if (pending.current || !confirmed) return; pending.current = true; setBusy(true); setError(''); try { await confirm(); onClose() } catch (e) { setError(message(e)) } finally { pending.current = false; setBusy(false) } }}>{busy ? 'Working…' : confirmLabel}</Button></div>
  </DialogContent></Dialog>
}
export interface Column {
  header: string
  /** Hide the column below a breakpoint to keep narrow screens readable. */
  hideBelow?: 'sm' | 'md' | 'lg' | 'xl'
  align?: 'right'
  /** Keep cell content on one line (IDs, dates). */
  nowrap?: boolean
}
const hidden = { sm: 'hidden sm:table-cell', md: 'hidden md:table-cell', lg: 'hidden lg:table-cell', xl: 'hidden xl:table-cell' }
const cellClass = (c: Column) => cn(c.hideBelow && hidden[c.hideBelow], c.align === 'right' && 'w-px text-right', c.nowrap ? 'whitespace-nowrap' : 'whitespace-normal')
const interactive = 'a,button,input,select,textarea,label,[role=menuitem],[role=dialog]'

/** DataTable renders a list. Columns may be plain headers or Column specs;
 * an "Actions" header (or `align: 'right'`) pins that column to the right.
 * With `rowHref` the whole row opens the item; controls inside it still
 * work. Keyboard users reach the item through the link in its first cell
 * (Tab, then Enter), so rows are not extra tab stops; the row highlights
 * while focus is inside it. `empty` replaces the default empty message. */
export function DataTable({ columns, rows, loading, error, retry, rowHref, empty }: { columns: (string | Column)[]; rows: ReactNode[][]; loading: boolean; error: string; retry: () => void; rowHref?: (index: number) => string; empty?: ReactNode }) {
  const navigate = useNavigate()
  const specs = columns.map(c => typeof c === 'string' ? { header: c, align: c === 'Actions' || c === '' ? 'right' as const : undefined } : c)
  if (loading) return <div role="status" className="space-y-3 py-4">{[1, 2, 3].map(i => <Skeleton key={i} className="h-10" />)}<span className="sr-only">Loading data…</span></div>
  if (error) return <ErrorState error={error} retry={retry} />
  if (!rows.length) return <>{empty ?? <EmptyState title="No results found" />}</>
  return <div className="overflow-hidden rounded-lg border bg-card"><Table>
    <TableHeader><TableRow className="hover:bg-transparent">{specs.map((c, i) => <TableHead key={i} className={cn(cellClass(c), 'whitespace-nowrap px-3 text-xs text-muted-foreground')}>{c.align === 'right' && (c.header === 'Actions' || !c.header) ? <span className="sr-only">Actions</span> : c.header}</TableHead>)}</TableRow></TableHeader>
    <TableBody>{rows.map((row, i) => {
      const href = rowHref?.(i)
      return <TableRow key={i} className={cn(href && 'cursor-pointer has-[:focus-visible]:bg-muted/50')} onClick={href ? e => { if (!(e.target as HTMLElement).closest(interactive) && !window.getSelection()?.toString()) navigate(href) } : undefined}>
        {row.map((cell, j) => <TableCell key={j} className={cn(specs[j] && cellClass(specs[j]), 'px-3 py-2.5')}>{cell}</TableCell>)}
      </TableRow>
    })}</TableBody>
  </Table></div>
}

/** EmptyState explains what belongs here and how to add the first one. */
export function EmptyState({ icon, title, description, action }: { icon?: ReactNode; title: string; description?: ReactNode; action?: ReactNode }) {
  return <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed px-6 py-14 text-center">
    {icon && <div className="mb-1 flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground [&_svg]:size-5">{icon}</div>}
    <p className="text-sm font-medium">{title}</p>
    {description && <p className="max-w-md text-sm text-muted-foreground">{description}</p>}
    {action && <div className="mt-2">{action}</div>}
  </div>
}

export function Status({ active, label }: { active: boolean; label?: string }) { return <Badge variant="secondary" className={active ? 'bg-success/10 text-success' : 'bg-muted text-muted-foreground'}>{label ?? (active ? 'Active' : 'Inactive')}</Badge> }
/** ID shows an identifier compactly (first block) with a copy button; the
 * full value is in the tooltip and on the clipboard. */
export function ID({ value }: { value: string }) { return <CopyText value={value} short /> }

/** shortId abbreviates a UUID to its first block for display. */
export function shortId(value: string) { return /^[0-9a-f]{8}-/i.test(value) ? `${value.slice(0, 8)}…` : value }

export function CopyButton({ value, label = 'Copy', className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false)
  return <Button type="button" variant="ghost" size="icon-xs" className={className} aria-label={copied ? 'Copied' : label} title={copied ? 'Copied' : label} onClick={async e => {
    e.stopPropagation()
    try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { toast.error('Copy failed — select the text instead') }
  }}>{copied ? <Check className="text-success" /> : <Copy />}</Button>
}

/** CopyText shows a monospace value (shortened when `short`) with a copy
 * button; the full value is in the tooltip. */
export function CopyText({ value, short, label }: { value: string; short?: boolean; label?: string }) {
  return <span className="group/copy inline-flex max-w-full items-center gap-0.5">
    <span className="truncate font-mono text-xs text-muted-foreground" title={value}>{short ? shortId(value) : value}</span>
    <CopyButton value={value} label={label ?? 'Copy ID'} className="opacity-60 group-hover/copy:opacity-100 focus-visible:opacity-100" />
  </span>
}

/** CopyField is a labelled read-only value with a copy button (client IDs,
 * secrets shown once, URLs to paste into another system). */
export function CopyField({ label, value, hint, secret }: { label: string; value: string; hint?: ReactNode; secret?: boolean }) {
  return <div className="space-y-1.5">
    <p className="text-sm font-medium">{label}</p>
    <div className={cn('flex items-start gap-2 rounded-lg border bg-muted/50 p-2', secret && 'border-warning/40')}>
      <code className="min-w-0 flex-1 break-all py-0.5 text-xs select-all">{value}</code>
      <CopyButton value={value} label={`Copy ${label.toLowerCase()}`} />
    </div>
    {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
  </div>
}

/** EntityRef names a referenced entity; it links when `to` is set and falls
 * back to the short ID when the name is unknown. */
export function EntityRef({ name, id, to, secondary }: { name?: string | null; id?: string | null; to?: string; secondary?: ReactNode }) {
  if (!id && !name) return <span className="text-muted-foreground">—</span>
  const label = name || (id ? shortId(id) : '')
  const main = to ? <Link to={to} className="font-medium text-foreground hover:text-primary hover:underline">{label}</Link> : <span className={cn(!name && 'font-mono text-xs text-muted-foreground')}>{label}</span>
  return <span className="block min-w-0" title={id ?? undefined}>{main}{secondary && <span className="block text-xs text-muted-foreground">{secondary}</span>}</span>
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })
const units: [Intl.RelativeTimeFormatUnit, number][] = [['year', 31536e6], ['month', 2592e6], ['week', 6048e5], ['day', 864e5], ['hour', 36e5], ['minute', 6e4]]
export function fromNow(date: Date, now = Date.now()) {
  const diff = date.getTime() - now
  for (const [unit, ms] of units) if (Math.abs(diff) >= ms) return relative.format(Math.round(diff / ms), unit)
  return diff > 0 ? 'in a moment' : 'just now'
}
export function formatDate(date: Date) { return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) }

/** Time shows a relative time ("in 3 days") with the exact date on hover. */
export function Time({ value, prefix }: { value: string | null | undefined; prefix?: string }) {
  if (!value) return <span className="text-muted-foreground">—</span>
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return <span className="text-muted-foreground">—</span>
  return <time dateTime={value} title={formatDate(date)} className="whitespace-nowrap">{prefix && `${prefix} `}{fromNow(date)}</time>
}

/** DetailSection is a titled card on detail pages. */
export function DetailSection({ title, description, actions, children, danger }: { title: string; description?: ReactNode; actions?: ReactNode; children: ReactNode; danger?: boolean }) {
  return <section className={cn('rounded-lg border bg-card', danger && 'border-destructive/40')}>
    <header className="flex flex-wrap items-start justify-between gap-3 border-b px-4 py-3">
      <div className="space-y-0.5"><h2 className={cn('text-sm font-semibold', danger && 'text-destructive')}>{title}</h2>{description && <p className="text-xs text-muted-foreground">{description}</p>}</div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </header>
    <div className="p-4">{children}</div>
  </section>
}

/** Property list for detail pages: label on the left, value on the right. */
export function Properties({ items }: { items: [string, ReactNode][] }) {
  return <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(8rem,auto)_1fr]">
    {items.map(([k, v]) => <div key={k} className="contents"><dt className="text-muted-foreground">{k}</dt><dd className="min-w-0 break-words">{v}</dd></div>)}
  </dl>
}

/** BackLink returns to the parent list on detail pages. */
export function BackLink({ to, children }: { to: string; children: ReactNode }) {
  return <Link to={to} className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground"><ArrowLeft className="size-3.5" />{children}</Link>
}
export function splitList(value: string | boolean) { return String(value).split(',').map(v => v.trim()).filter(Boolean) }
