// Shared base for the launch video: serves the built operator console, signs
// in a fictional operator and answers /management/v1 with demo data.
// No real credentials or customer data are involved.
import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { chromium } from 'playwright-core'
import { api as base, ENV, PROJECT } from './demo-data.mjs'
import { extra } from './demo-extra.mjs'

const api = { ...base, ...extra }

export { chromium, ENV, PROJECT }
const here = path.dirname(fileURLToPath(import.meta.url))
export const frontend = path.resolve(here, '../../frontend')
export const consoleDist = path.join(tmpdir(), 'iam-console')
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.json': 'application/json', '.png': 'image/png' }

/** Builds the console outside the repo (frontend/dist is untouched). */
export function buildConsole() {
  execFileSync('npx', ['vite', 'build', '--outDir', consoleDist, '--emptyOutDir', '--logLevel', 'error'], { cwd: frontend, stdio: 'inherit' })
}

/** Static server with SPA fallback; returns { url, stop }. */
export async function startConsole(port = 4176) {
  if (!existsSync(path.join(consoleDist, 'index.html'))) buildConsole()
  const server = createServer(async (req, res) => {
    const pathname = new URL(req.url, 'http://x').pathname
    let file = path.join(consoleDist, pathname)
    if (!existsSync(file) || pathname.endsWith('/')) file = path.join(consoleDist, 'index.html')
    res.setHeader('content-type', types[path.extname(file)] ?? 'application/octet-stream')
    res.end(await readFile(file))
  })
  await new Promise(ok => server.listen(port, '127.0.0.1', ok))
  return { url: `http://127.0.0.1:${port}`, stop: () => server.close() }
}

/**
 * Opens a signed-in console page. `handle(method, path, url, request)` may
 * answer before the static data: return JSON, { status, json } or undefined.
 */
export async function openConsole(browser, { theme = 'dark', handle } = {}) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1.5, locale: 'en-US', timezoneId: 'UTC', colorScheme: theme })
  const page = await context.newPage()
  await page.clock.setFixedTime(new Date('2026-10-07T17:00:00Z'))
  await page.addInitScript(t => { localStorage.setItem('iamkit-theme', t); localStorage.setItem('iamkit-locale', 'en') }, theme)
  await page.route('**/management/v1/**', async r => {
    const url = new URL(r.request().url())
    const p = url.pathname.replace(/^\/management\/v1/, '')
    const method = r.request().method()
    const custom = handle && await handle(method, p, url, r.request())
    if (custom !== undefined) return r.fulfill(typeof custom === 'object' && custom !== null && 'json' in custom ? custom : { json: custom })
    if (method !== 'GET') return r.fulfill({ json: {} })
    const body = api[p]
    if (typeof body === 'function') return r.fulfill({ json: body(url) })
    if (body !== undefined) return r.fulfill({ json: body })
    return r.fulfill({ status: 404, json: { error: { code: 'not_found', message: `no demo data for ${p}` } } })
  })
  return { context, page }
}

export const envUrl = (base, p = '') => `${base}/projects/${PROJECT}/environments/${ENV}${p}`
