import { useRef, useState } from 'react'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { t } from '@/lib/i18n'

interface TagInputProps {
  id?: string
  name: string
  defaultValue?: string[]
  disabled?: boolean
  placeholder?: string
  className?: string
  /** Auto-prefix: user types "read" → "invoices:read" */
  prefix?: string
  /** Called with the tags after each change */
  onChange?: (tags: string[]) => void
}

export function TagInput({ id, name, defaultValue, disabled, placeholder, className, prefix, onChange }: TagInputProps) {
  const [tags, setTagsState] = useState<string[]>(defaultValue ?? [])
  const setTags = (update: (prev: string[]) => string[]) => setTagsState(prev => {
    const next = update(prev)
    if (onChange && next !== prev) queueMicrotask(() => onChange(next))
    return next
  })
  const [input, setInput] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const applyPrefix = (v: string): string => {
    if (!prefix) return v
    // If user already typed the full prefix, keep as-is
    if (v.startsWith(prefix + ':')) return v
    return `${prefix}:${v}`
  }

  const addTags = (raw: string) => {
    const incoming = raw.split(/[,\n]/).map(s => s.trim()).filter(Boolean).map(applyPrefix)
    if (!incoming.length) return
    setTags(prev => {
      const set = new Set(prev)
      for (const tag of incoming) set.add(tag)
      return [...set]
    })
    setInput('')
  }

  const removeTag = (index: number) => setTags(prev => prev.filter((_, i) => i !== index))

  return (
    <div className={cn('flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border border-input bg-transparent px-2 py-1.5 text-sm focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50', disabled && 'opacity-50', className)} onClick={() => inputRef.current?.focus()}>
      <input type="hidden" name={name} value={tags.join(',')} />
      {tags.map((tag, i) => (
        <span key={tag} className="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 font-mono text-xs">
          {tag}
          {!disabled && (
            <button type="button" className="ml-0.5 rounded-sm text-muted-foreground hover:text-foreground" onClick={e => { e.stopPropagation(); removeTag(i) }} aria-label={t('Remove {{tag}}', { tag })}>
              <X className="size-3" />
            </button>
          )}
        </span>
      ))}
      <input
        ref={inputRef}
        id={id}
        type="text"
        value={input}
        disabled={disabled}
        placeholder={tags.length ? t('Add more…') : placeholder ?? (prefix ? t('Type action (auto-prefixed as {{prefix}}:…)', { prefix }) : t('Type and press Enter…'))}
        className="min-w-[120px] flex-1 bg-transparent outline-none placeholder:text-muted-foreground disabled:cursor-not-allowed"
        onChange={e => setInput(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter') { e.preventDefault(); addTags(input) }
          if (e.key === 'Backspace' && !input && tags.length) { e.preventDefault(); removeTag(tags.length - 1) }
        }}
        onPaste={e => {
          const pasted = e.clipboardData.getData('text')
          if (pasted.includes(',') || pasted.includes('\n')) { e.preventDefault(); addTags(pasted) }
        }}
        onBlur={() => { if (input.trim()) addTags(input) }}
      />
    </div>
  )
}
