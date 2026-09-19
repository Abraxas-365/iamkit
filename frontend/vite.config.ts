import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(import.meta.dirname, './src') } },
  server: {
    host: 'localhost',
    https: process.env.CONSOLE_TLS_CERT && process.env.CONSOLE_TLS_KEY ? {
      cert: readFileSync(process.env.CONSOLE_TLS_CERT),
      key: readFileSync(process.env.CONSOLE_TLS_KEY),
    } : undefined,
    proxy: Object.fromEntries(
      ['/management', '/identity', '/api', '/scim', '/health', '/.well-known'].map(
        p => [p, { target: process.env.IAMKIT_API_URL || 'http://localhost:8080' }]
      )
    ),
  },
})
