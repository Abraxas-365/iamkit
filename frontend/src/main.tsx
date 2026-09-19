import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { ThemeProvider } from 'next-themes'
import { Toaster } from '@/components/ui/sonner'
import { AuthProvider } from '@/lib/auth'
import App from './App'
import './index.css'
createRoot(document.getElementById('root')!).render(
  <StrictMode><ThemeProvider attribute="class" defaultTheme="dark" enableSystem storageKey="iamkit-theme"><BrowserRouter><AuthProvider><App /><Toaster /></AuthProvider></BrowserRouter></ThemeProvider></StrictMode>,
)
