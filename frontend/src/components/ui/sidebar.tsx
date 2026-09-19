import * as React from 'react'
import { mergeProps } from '@base-ui/react/merge-props'
import { useRender } from '@base-ui/react/use-render'
import { PanelLeftIcon } from 'lucide-react'
import { useIsMobile } from '@/hooks/use-mobile'
import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'

// FreeRouter's inset/off-canvas sidebar, retaining the primitives used by IAM.
const SidebarContext = React.createContext<{
  open: boolean; openMobile: boolean; isMobile: boolean;
  setOpenMobile: (open: boolean) => void; toggleSidebar: () => void;
} | null>(null)

function useSidebar() {
  const context = React.useContext(SidebarContext)
  if (!context) throw new Error('useSidebar must be used within a SidebarProvider.')
  return context
}

function SidebarProvider({ children }: { children: React.ReactNode }) {
  const isMobile = useIsMobile()
  const [open, setOpen] = React.useState(true)
  const [openMobile, setOpenMobile] = React.useState(false)
  const toggleSidebar = React.useCallback(() => {
    if (isMobile) setOpenMobile(value => !value)
    else setOpen(value => !value)
  }, [isMobile])
  React.useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'b' && (event.metaKey || event.ctrlKey)) {
        event.preventDefault()
        toggleSidebar()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [toggleSidebar])
  return <SidebarContext.Provider value={{ open, openMobile, setOpenMobile, isMobile, toggleSidebar }}>
    <div data-slot="sidebar-wrapper" style={{ '--sidebar-width': '16rem' } as React.CSSProperties} className="group/sidebar-wrapper flex min-h-svh w-full has-data-[variant=inset]:bg-sidebar">{children}</div>
  </SidebarContext.Provider>
}

function Sidebar({ children }: { children: React.ReactNode }) {
  const { open, openMobile, setOpenMobile, isMobile } = useSidebar()
  if (isMobile) return <Sheet open={openMobile} onOpenChange={setOpenMobile}>
    <SheetContent data-slot="sidebar" data-mobile="true" className="w-72 bg-sidebar p-0 text-sidebar-foreground">
      <SheetHeader className="sr-only"><SheetTitle>Navigation</SheetTitle><SheetDescription>IAMKit console navigation.</SheetDescription></SheetHeader>
      <div className="flex h-full w-full flex-col">{children}</div>
    </SheetContent>
  </Sheet>
  return <div className="group peer hidden text-sidebar-foreground md:block" data-state={open ? 'expanded' : 'collapsed'} data-collapsible={open ? '' : 'offcanvas'} data-variant="inset" data-side="left" data-slot="sidebar">
    <div data-slot="sidebar-gap" className="relative w-(--sidebar-width) bg-transparent transition-[width] duration-200 ease-linear group-data-[collapsible=offcanvas]:w-0" />
    <div data-slot="sidebar-container" className="fixed inset-y-0 left-0 z-10 hidden h-svh w-(--sidebar-width) p-2 transition-[left,right,width] duration-200 ease-linear group-data-[collapsible=offcanvas]:left-[calc(var(--sidebar-width)*-1)] md:flex">
      <div data-slot="sidebar-inner" className="flex size-full flex-col bg-sidebar">{children}</div>
    </div>
  </div>
}

function SidebarTrigger({ className, onClick, ...props }: React.ComponentProps<typeof Button>) {
  const { toggleSidebar } = useSidebar()
  return <Button data-slot="sidebar-trigger" variant="ghost" size="icon-sm" className={className} onClick={event => { onClick?.(event); toggleSidebar() }} {...props}><PanelLeftIcon /><span className="sr-only">Toggle Sidebar</span></Button>
}
function SidebarRail() {
  const { toggleSidebar } = useSidebar()
  return <button data-slot="sidebar-rail" aria-label="Toggle Sidebar" tabIndex={-1} onClick={toggleSidebar} title="Toggle Sidebar" className="absolute inset-y-0 -right-4 z-20 hidden w-4 -translate-x-1/2 cursor-w-resize transition-all ease-linear after:absolute after:inset-y-0 after:start-1/2 after:w-[2px] hover:after:bg-sidebar-border sm:flex" />
}
function SidebarInset({ className, ...props }: React.ComponentProps<'main'>) {
  return <main data-slot="sidebar-inset" className={cn('relative flex w-full flex-1 flex-col bg-background md:peer-data-[variant=inset]:m-2 md:peer-data-[variant=inset]:ml-0 md:peer-data-[variant=inset]:rounded-xl md:peer-data-[variant=inset]:shadow-sm md:peer-data-[variant=inset]:peer-data-[state=collapsed]:ml-2', className)} {...props} />
}
function SidebarHeader({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sidebar-header" className={cn('flex flex-col gap-2 p-2', className)} {...props} /> }
function SidebarFooter({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sidebar-footer" className={cn('flex flex-col gap-2 p-2', className)} {...props} /> }
function SidebarSeparator({ className, ...props }: React.ComponentProps<typeof Separator>) { return <Separator data-slot="sidebar-separator" className={cn('mx-2 w-auto bg-sidebar-border', className)} {...props} /> }
function SidebarContent({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sidebar-content" className={cn('no-scrollbar flex min-h-0 flex-1 flex-col gap-0 overflow-auto', className)} {...props} /> }
function SidebarGroup({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sidebar-group" className={cn('relative flex w-full min-w-0 flex-col p-2', className)} {...props} /> }
function SidebarGroupLabel({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sidebar-group-label" className={cn('flex h-8 shrink-0 items-center rounded-md px-2 text-xs font-medium text-sidebar-foreground/70', className)} {...props} /> }
function SidebarGroupContent({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="sidebar-group-content" className={cn('w-full text-sm', className)} {...props} /> }
function SidebarMenu({ className, ...props }: React.ComponentProps<'ul'>) { return <ul data-slot="sidebar-menu" className={cn('flex w-full min-w-0 flex-col gap-0', className)} {...props} /> }
function SidebarMenuItem({ className, ...props }: React.ComponentProps<'li'>) { return <li data-slot="sidebar-menu-item" className={cn('group/menu-item relative', className)} {...props} /> }
function SidebarMenuButton({ render, isActive = false, className, ...props }: useRender.ComponentProps<'button'> & React.ComponentProps<'button'> & { isActive?: boolean }) {
  return useRender({
    defaultTagName: 'button', render,
    props: mergeProps<'button'>({ className: cn('peer/menu-button group/menu-button flex h-8 w-full items-center gap-2 overflow-hidden rounded-md p-2 text-left text-sm ring-sidebar-ring outline-hidden transition-[width,height,padding] hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 active:bg-sidebar-accent active:text-sidebar-accent-foreground disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50 data-active:bg-sidebar-accent data-active:font-medium data-active:text-sidebar-accent-foreground [&_svg]:size-4 [&_svg]:shrink-0 [&>span:last-child]:truncate', className) }, props),
    state: { slot: 'sidebar-menu-button', sidebar: 'menu-button', active: isActive },
  })
}
export { Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent, SidebarGroupLabel, SidebarHeader, SidebarInset, SidebarMenu, SidebarMenuButton, SidebarMenuItem, SidebarProvider, SidebarRail, SidebarSeparator, SidebarTrigger, useSidebar }
