import * as React from 'react'
import { Dialog as SheetPrimitive } from '@base-ui/react/dialog'
import { XIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'

function Sheet(props: SheetPrimitive.Root.Props) { return <SheetPrimitive.Root data-slot="sheet" {...props} /> }
function SheetContent({ className, children, ...props }: SheetPrimitive.Popup.Props) {
  return <SheetPrimitive.Portal>
    <SheetPrimitive.Backdrop className="fixed inset-0 z-50 bg-black/10 transition-opacity duration-150 data-ending-style:opacity-0 data-starting-style:opacity-0 supports-backdrop-filter:backdrop-blur-xs" />
    <SheetPrimitive.Popup data-slot="sheet-content" className={cn('fixed inset-y-0 left-0 z-50 flex h-full w-3/4 flex-col gap-4 border-r bg-popover bg-clip-padding text-sm text-popover-foreground shadow-lg transition duration-200 ease-in-out data-ending-style:-translate-x-10 data-starting-style:-translate-x-10 data-ending-style:opacity-0 data-starting-style:opacity-0 sm:max-w-sm', className)} {...props}>
      {children}
      <SheetPrimitive.Close render={<Button variant="ghost" className="absolute top-3 right-3" size="icon-sm" />}><XIcon /><span className="sr-only">Close</span></SheetPrimitive.Close>
    </SheetPrimitive.Popup>
  </SheetPrimitive.Portal>
}
function SheetHeader({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sheet-header" className={cn('flex flex-col gap-0.5 p-4', className)} {...props} /> }
function SheetTitle({ className, ...props }: SheetPrimitive.Title.Props) { return <SheetPrimitive.Title className={cn('font-heading text-base font-medium text-foreground', className)} {...props} /> }
function SheetDescription({ className, ...props }: SheetPrimitive.Description.Props) { return <SheetPrimitive.Description className={cn('text-sm text-muted-foreground', className)} {...props} /> }
export { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription }
