import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ThemeProvider } from 'next-themes'
import { Toaster } from '@/components/ui/sonner'
import { AuthProvider } from '@/lib/auth'
import App from './App'
import './index.css'
// next-themes renders an inline anti-flash <script> meant for server
// rendering; in this client-only SPA React never runs it and warns. A
// non-JavaScript type makes it an inert data block, which React accepts.
const themeScript = { type: 'text/plain' }
createRoot(document.getElementById('root')!).render(
  <StrictMode><ThemeProvider attribute="class" defaultTheme="dark" enableSystem storageKey="iamkit-theme" scriptProps={themeScript}><BrowserRouter><AuthProvider><App /><Toaster /></AuthProvider></BrowserRouter></ThemeProvider></StrictMode>,
)
