import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { PaginatedState } from '@/hooks/use-paginated-list'
import { t } from '@/lib/i18n'

interface PaginationBarProps {
  /** The paginated state from usePaginatedList. */
  state: Pick<PaginatedState<unknown>, 'rawSearch' | 'setSearch' | 'from' | 'to' | 'total' | 'hasPrev' | 'hasNext' | 'nextPage' | 'prevPage'>
  /** Search input placeholder. */
  placeholder?: string
  /** aria-label for the search input. */
  label?: string
  /** Noun for the count label, e.g. "members". Defaults to "records". */
  noun?: string
}

export function PaginationBar({ state, placeholder, label, noun = 'records' }: PaginationBarProps) {
  const { rawSearch, setSearch, from, to, total, hasPrev, hasNext, nextPage, prevPage } = state

  return (
    <div className="flex items-center justify-between gap-3">
      <Input
        aria-label={label ?? t('Search {{noun}}', { noun })}
        className="max-w-sm"
        placeholder={placeholder ?? t('Search {{noun}}…', { noun })}
        value={rawSearch}
        onChange={e => setSearch(e.target.value)}
      />
      <div className="flex items-center gap-2">
        <span className="whitespace-nowrap text-xs text-muted-foreground">
          {total === 0 ? `0 ${noun}` : t('{{from}}–{{to}} of {{total}} {{noun}}', { from, to, total, noun })}
        </span>
        {(hasPrev || hasNext) && (
          <>
            <Button variant="outline" size="icon" className="size-7" disabled={!hasPrev} onClick={prevPage} aria-label={t('Previous page')}>
              <ChevronLeft className="size-4" />
            </Button>
            <Button variant="outline" size="icon" className="size-7" disabled={!hasNext} onClick={nextPage} aria-label={t('Next page')}>
              <ChevronRight className="size-4" />
            </Button>
          </>
        )}
      </div>
    </div>
  )
}
