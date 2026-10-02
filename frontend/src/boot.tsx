import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import { ThemeProvider } from 'next-themes'
import { Toaster } from '@/components/ui/sonner'
import { AuthProvider } from '@/lib/auth'
import App from './App'
import OrgAdminPortal from './org-admin/portal'
import './index.css'
// next-themes renders an inline anti-flash <script> meant for server
// rendering; in this client-only SPA React never runs it and warns. A
// non-JavaScript type makes it an inert data block, which React accepts.
const themeScript = { type: 'text/plain' }
// A data router (rather than <BrowserRouter>) so editors can block in-app
// navigation while they hold unsaved changes (useBlocker). App keeps its
// own <Routes> tree under one catch-all route.
const router = createBrowserRouter([
  // The organization admin portal signs end users in through OAuth: it
  // never uses the operator session, so it stays outside AuthProvider.
  { path: '/org-admin/*', element: <OrgAdminPortal /> },
  { path: '*', element: <AuthProvider><App /><Toaster /></AuthProvider> },
])
createRoot(document.getElementById('root')!).render(
  <StrictMode><ThemeProvider attribute="class" defaultTheme="dark" enableSystem storageKey="iamkit-theme" scriptProps={themeScript}><RouterProvider router={router} /></ThemeProvider></StrictMode>,
)
