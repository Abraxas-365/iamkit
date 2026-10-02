import { useContext, useEffect, type RefObject } from 'react'
import { UNSAFE_DataRouterContext, useBlocker } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'
import { t } from '@/lib/i18n'

/** UnsavedChangesGuard asks before the user leaves a page with unsaved work:
 * a confirm dialog for links and back/forward inside the console, and the
 * browser's own prompt for reloads, closed tabs and external links. Leaving
 * for the same path (e.g. a query change) is not blocked. Set `bypass` to
 * true just before leaving on purpose (after Discard or Delete). */
export function UnsavedChangesGuard({ when, bypass, message = t('Your changes on this page have not been saved.') }: { when: boolean; bypass?: RefObject<boolean>; message?: string }) {
  useEffect(() => {
    if (!when) return
    const warn = (e: BeforeUnloadEvent) => { e.preventDefault() }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [when])
  // In-app blocking needs a data router; plain routers (some tests) get only
  // the browser prompt.
  return useContext(UNSAFE_DataRouterContext) ? <NavigationGuard when={when} bypass={bypass} message={message} /> : null
}

function NavigationGuard({ when, bypass, message }: { when: boolean; bypass?: RefObject<boolean>; message: string }) {
  const blocker = useBlocker(({ currentLocation, nextLocation }) => when && !bypass?.current && currentLocation.pathname !== nextLocation.pathname)
  if (blocker.state !== 'blocked') return null
  return <Dialog open onOpenChange={open => { if (!open) blocker.reset() }}>
    <DialogContent className="sm:max-w-md">
      <DialogTitle className="text-base font-semibold">{t('Leave without saving?')}</DialogTitle>
      <DialogDescription>{t('{{message}} If you leave now, they are lost.', { message })}</DialogDescription>
      <div className="flex justify-end gap-2">
        <Button variant="outline" autoFocus onClick={() => blocker.reset()}>{t('Keep editing')}</Button>
        <Button variant="destructive" onClick={() => blocker.proceed()}>{t('Discard changes')}</Button>
      </div>
    </DialogContent>
  </Dialog>
}
