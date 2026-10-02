import { cn } from '@/lib/utils'
import { t } from '@/lib/i18n'

// PreviewFrame shows a server-rendered hosted page. The frame is fully
// sandboxed: no scripts, forms, navigation or popups.
export function PreviewFrame({ html, className, title = t('Hosted page preview') }: { html: string; className?: string; title?: string }) {
  return <iframe title={title} sandbox="" srcDoc={html} className={cn('block w-full border-0 bg-white', className)} />
}

export function clientName(c?: { application_name: string; resource_name: string }) {
  return c ? [c.application_name, c.resource_name].filter(Boolean).join(' · ') : ''
}
