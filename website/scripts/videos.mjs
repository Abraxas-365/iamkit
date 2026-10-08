// IAMKit launch videos (1920×1080, with music), in English: one pool of takes, three
// storyboards for three kinds of buyer (platform / security / multi-tenant SaaS).
//
//   npm run videos            # builds the console, records, composes and mixes
//   npm run videos -- --reuse # recomposes without re-recording (takes live in tmp)
//   npm run videos -- --only users,keys   # re-records just those takes (merged into the saved ones)
//   npm run videos -- --video security    # composes only that video (platform | security | saas)
//
// 1. Takes: Playwright drives the real operator console (frontend/, built to
//    the tmp dir, never to frontend/dist) with fictional data and a stateful
//    simulator for creating and assigning a role. The hosted sign-in pages are
//    the real server-rendered HTML (scripts/video/hosted). Each take notes its
//    clicks, camera moves and "pops" (data that jumps out).
// 2. Composition: scripts/video/stage.html draws every frame as a pure function
//    of time (big type, wipes, the window with the take and its camera).
// 3. Audio: music + effects on clicks, pops and text (scripts/video/audio, from
//    the /brag skill: ende.app music, CC BY 4.0, and CC0 effects by Kenney).
//
// Output: public/videos/iamkit-{platform,security,saas}.{mp4,webm,jpg}.
import { execFileSync, spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { chromium, envUrl, openConsole, startConsole, buildConsole } from './harness.mjs'
import { liveSim } from './demo-extra.mjs'
import { enterpriseSim, enterpriseTakes } from './enterprise-demo.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const site = path.resolve(here, '..')
const out = path.join(site, 'public/videos')
const work = path.join(tmpdir(), 'iam-video')
const arg = n => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : undefined }
const only = arg('only')?.split(',')
const reuse = process.argv.includes('--reuse') || !!only
const wanted = arg('video')?.split(',')
const FPS = 30
const W = 1920, H = 1080
const ff = (...a) => execFileSync('ffmpeg', ['-y', '-loglevel', 'error', ...a])

// ── Own cursor: arrow and a ripple on click ──
const cursorScript = () => {
  const make = () => {
    if (document.getElementById('v-cursor')) return
    const style = document.createElement('style')
    style.textContent = `
      #v-cursor{position:fixed;left:0;top:0;width:30px;height:30px;z-index:2147483647;pointer-events:none;transform:translate(-100px,-100px);filter:drop-shadow(0 3px 4px rgba(0,0,0,.5))}
      .v-ripple{position:fixed;z-index:2147483646;pointer-events:none;width:16px;height:16px;margin:-8px 0 0 -8px;border-radius:50%;background:rgba(123,155,174,.45);border:2px solid #7b9bae;animation:v-ripple .5s ease-out forwards}
      @keyframes v-ripple{to{transform:scale(4);opacity:0}}`
    document.head.appendChild(style)
    const c = document.createElement('div')
    c.id = 'v-cursor'
    c.innerHTML = '<svg viewBox="0 0 24 24" width="30" height="30"><path d="M4 2l15 9-6.5 1.6L9.6 19z" fill="#f2efe8" stroke="#0c0c0a" stroke-width="1.6" stroke-linejoin="round"/></svg>'
    document.body.appendChild(c)
    addEventListener('mousemove', e => { window.__mx = e.clientX; window.__my = e.clientY; c.style.transform = `translate(${e.clientX - 4}px,${e.clientY - 2}px)` }, true)
    addEventListener('mousedown', e => {
      const r = document.createElement('div')
      r.className = 'v-ripple'
      r.style.left = `${e.clientX}px`
      r.style.top = `${e.clientY}px`
      document.body.appendChild(r)
      setTimeout(() => r.remove(), 600)
    }, true)
  }
  if (document.readyState === 'loading') addEventListener('DOMContentLoaded', make)
  else make()
}

/** Tools of a take: everything it notes is in seconds from its start. */
function take(page) {
  let t0 = 0, cdp = null, pos = { x: 900, y: 500 }
  const shots = [] // { at, data }: frames at real resolution (CDP honours deviceScaleFactor)
  const log = { cams: [], clicks: [], pops: [], caps: [], cur: [] }
  const now = () => (Date.now() - t0) / 1000
  const center = async target => {
    if (!target.boundingBox) return target
    const b = await target.boundingBox()
    return { x: b.x + b.width / 2, y: b.y + b.height / 2 }
  }
  return {
    log,
    shots,
    pause: ms => page.waitForTimeout(ms),
    async start() {
      pos = await page.evaluate(() => ({ x: window.__mx ?? 900, y: window.__my ?? 500 }))
      cdp = await page.context().newCDPSession(page)
      cdp.on('Page.screencastFrame', f => {
        shots.push({ at: now(), data: Buffer.from(f.data, 'base64') })
        cdp.send('Page.screencastFrameAck', { sessionId: f.sessionId }).catch(() => {})
      })
      t0 = Date.now()
      await cdp.send('Page.startScreencast', { format: 'jpeg', quality: 90, maxWidth: 2880, maxHeight: 1800, everyNthFrame: 1 })
    },
    async stop() {
      log.duration = now()
      await cdp.send('Page.stopScreencast')
    },
    /** Camera: centre on the element (or {x,y}) at that zoom (capped: the cursor stays in frame). */
    async cam(target, zoom, dur = .7) { log.cams.push({ t: now(), ...(await center(target)), zoom: Math.min(zoom, 1.12), dur }) },
    at: center,
    /** Slides the cursor to {x,y} in `ms` (ease in-out) and notes the path for the camera. */
    async glide({ x, y }, ms = 600) {
      const a = pos, t = Date.now()
      let last = -1
      log.cur.push({ t: now(), x: a.x, y: a.y })
      for (;;) {
        const p = Math.min(1, (Date.now() - t) / ms), e = p < .5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2
        const cx = a.x + (x - a.x) * e, cy = a.y + (y - a.y) * e
        await page.mouse.move(cx, cy)
        if (now() - last > .05 || p >= 1) { log.cur.push({ t: now(), x: cx, y: cy }); last = now() }
        if (p >= 1) break
        await page.waitForTimeout(12)
      }
      pos = { x, y }
    },
    async click(locator, ms = 650) {
      await locator.scrollIntoViewIfNeeded()
      const target = await center(locator)
      await this.glide(target, ms)
      await page.waitForTimeout(260)
      log.clicks.push(now())
      await locator.click()
      pos = target
      await page.waitForTimeout(180)
    },
    async type(locator, text, delay = 70) { await locator.pressSequentially(text, { delay }) },
    async scrollTo(locator) {
      await locator.evaluate(el => el.scrollIntoView({ behavior: 'smooth', block: 'center' }))
      await page.waitForTimeout(900)
    },
    cap(title, sub) { log.caps.push({ t: now(), title, sub }) },
    pop(text, label, dur = 2.6) { log.pops.push({ t: now(), text, label, dur }) },
  }
}

const hosted = name => path.join(here, 'video/hosted', `iam-hosted-${name}.html`)
const row = (page, text) => page.getByRole('row').filter({ hasText: text }).first()
const menuItem = (page, name) => page.getByRole('menuitem', { name })

// ── Takes ──
// Everything is real time and slow: the cursor glides, text is typed letter by letter and
// every step carries its caption (k.cap) so a viewer follows what is happening.
const tomas = {
  async home(page, url, k) {
    await page.goto(envUrl(url))
    await page.getByRole('heading', { name: 'Recent changes' }).waitFor()
    await page.getByText('12480').waitFor()
    await page.mouse.move(1300, 120)
    await k.start()
    k.cap('Your identity stack, in view', 'One console per environment')
    await k.pause(500)
    for (const [x, y] of [[380, 235], [640, 235], [900, 235], [1160, 235]]) await k.glide({ x, y }, 520)
    k.pop('12,480 users', '38 organizations · one environment')
    await k.pause(1300)
    k.cap('Recent changes, as they happen', 'Every operator action is audited')
    await k.glide({ x: 1000, y: 560 }, 800)
    await k.pause(1600)
  },

  async apps(page, url, k) {
    await page.goto(envUrl(url, '/applications'))
    await page.getByText('Partner Portal').waitFor()
    await page.mouse.move(1000, 160)
    await k.start()
    k.cap('Register your apps', 'Web, mobile, partners and workers')
    await k.pause(900)
    await k.glide(await k.at(page.getByText('Northwind Mobile').first()), 700)
    await k.pause(500)
    await k.click(row(page, 'Northwind Web').getByText('Northwind Web').first(), 700)
    await page.getByText('OAuth clients').first().waitFor()
    await k.pause(500)
    k.cap('Each app, its clients', 'Redirect URIs, resources and credentials')
    await k.scrollTo(page.getByText('OAuth clients').first())
    await k.pause(600)
    const link = page.locator('a[href*="/oauth-clients/"]').first()
    await k.click(link, 700)
    await page.getByText('Private key JWT').first().waitFor()
    k.cap('Secure by default', 'Signed client assertions, exact redirect match')
    await k.glide(await k.at(page.getByText('Private key JWT').first()), 700)
    k.pop('private_key_jwt', 'No shared secret leaves your server')
    await k.pause(1800)
  },

  async role(page, url, k) {
    await page.goto(envUrl(url, '/roles'))
    await page.getByText('Billing analyst').waitFor()
    await page.mouse.move(900, 400)
    await k.start()
    k.cap('Define a role', 'Permissions belong to a resource')
    await k.pause(700)
    await k.click(page.getByRole('button', { name: 'Create role' }))
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    await k.pause(300)
    await k.click(dialog.getByRole('textbox', { name: 'Name' }), 500)
    await k.type(dialog.getByRole('textbox', { name: 'Name' }), 'Refund approver', 60)
    await k.click(dialog.getByRole('combobox'), 600)
    await page.getByRole('listitem').filter({ hasText: 'Billing API' }).waitFor()
    await k.click(page.getByRole('listitem').filter({ hasText: 'Billing API' }), 500)
    await dialog.getByText('billing:refund').waitFor()
    k.cap('Tick only what it needs', 'Least privilege, per API')
    await k.click(dialog.getByText('billing:read'), 500)
    await k.click(dialog.getByText('billing:refund'), 400)
    await k.click(dialog.getByRole('button', { name: 'Save' }), 500)
    await page.getByText('Refund approver').first().waitFor()
    k.cap('Ready to assign', 'Roles show up everywhere at once')
    k.pop('Role created', 'Refund approver · 2 permissions')
    await k.pause(1800)
  },

  async assign(page, url, k) {
    await page.goto(envUrl(url, '/roles'))
    await page.getByText('Billing analyst').waitFor()
    await page.mouse.move(900, 400)
    await k.start()
    k.cap('Give someone access', 'A role, for one person, in one organization')
    await k.pause(600)
    await k.click(page.getByRole('button', { name: 'Assign role' }))
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    const options = name => page.getByRole('listitem').filter({ hasText: name }).first()
    await k.click(dialog.getByRole('combobox').nth(0), 600)
    await k.click(options('Acme Logistics'), 450)
    await k.click(dialog.getByRole('combobox').nth(1), 500)
    await k.click(options('Maya Chen'), 450)
    await k.click(dialog.getByRole('combobox').nth(2), 500)
    await k.click(options('Billing analyst'), 450)
    await k.click(dialog.getByRole('button', { name: 'Assign role' }), 500)
    await page.getByText('Role assigned').waitFor()
    k.cap('Done. Auditable.', 'Who granted what, and when')
    k.pop('Role assigned', 'Maya Chen · Acme Logistics')
    await k.pause(1700)
  },

  async login(page, url, k) {
    const serve = name => page.route(`**/hosted-demo/${name}.html`, r => r.fulfill({ path: hosted(name), contentType: 'text/html' }))
    await serve('northwind-identify'); await serve('lumen-identify')
    const open = async name => {
      await page.goto(`${url}/hosted-demo/${name}.html`)
      await page.locator('#email').waitFor()
      await page.evaluate(() => document.querySelectorAll('form').forEach(f => f.addEventListener('submit', e => e.preventDefault())))
    }
    await open('northwind-identify')
    await page.mouse.move(1000, 700)
    await k.start()
    k.cap('Hosted sign-in, your brand', 'Real pages, served by IAMKit')
    k.pop('Northwind', 'Your brand · dark')
    await k.click(page.locator('#email'), 700)
    await k.type(page.locator('#email'), 'maya@acme-logistics.example', 55)
    await k.pause(900)
    await open('lumen-identify')
    k.cap('Another product, same engine', 'Per-application look and wording')
    k.pop('Lumen Health', 'Light · its own colours')
    await k.click(page.locator('#email'), 600)
    await k.type(page.locator('#email'), 'sam@lumenhealth.example', 55)
    await k.pause(1400)
  },

  async users(page, url, k) {
    await page.goto(envUrl(url, '/users'))
    await page.getByText('Tomás Berg').waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Find any user', 'Search, filter by state, people or machines')
    await k.glide(await k.at(page.getByText('Tomás Berg').first()), 800)
    k.pop('Locked', 'Five wrong passwords · Brightside Health')
    await k.pause(900)
    await k.click(row(page, 'Tomás Berg').getByText('Tomás Berg').first(), 300)
    await page.getByText('Locked after 5 wrong passwords').waitFor()
    k.cap('Brute force, stopped', 'Lockout comes from your password policy')
    await k.pause(1500)
    await k.click(page.getByRole('button', { name: 'Unlock' }), 700)
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    k.cap('Support can unlock in one click', 'Or a password reset does it')
    await k.pause(600)
    await k.click(dialog.getByRole('button', { name: 'Unlock' }), 600)
    await page.getByText('Locked after 5 wrong passwords').waitFor({ state: 'detached' })
    k.pop('Unlocked', 'Tomás can sign in again')
    await k.pause(1600)
  },

  async sessions(page, url, k) {
    await page.goto(envUrl(url, '/sessions'))
    await page.getByText('Impersonation').waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Every active session', 'Which app, which organization, until when')
    await k.pause(800)
    await k.glide(await k.at(page.getByText('Impersonation').first()), 900)
    k.pop('Impersonation', 'priya@northwind.example · Ticket 4821')
    await k.pause(1500)
    k.cap('Revoke what you don’t trust', 'The user signs in again at the next refresh')
    await k.click(page.getByRole('button', { name: 'Actions for session of daniel@acme-logistics.example' }), 800)
    await k.click(menuItem(page, 'Revoke session'), 500)
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    await k.pause(700)
    await k.click(dialog.getByRole('button', { name: 'Revoke session' }), 600)
    await row(page, 'Daniel Okafor').getByText('Revoked').waitFor()
    k.pop('Session revoked', 'Daniel Okafor · Northwind Mobile')
    await k.pause(1700)
  },

  async policy(page, url, k) {
    await page.goto(envUrl(url, '/sign-in-policy'))
    await page.getByText('Require a second factor everywhere').waitFor()
    await page.mouse.move(1000, 250)
    await k.start()
    k.cap('Choose how people sign in', 'Passwords, codes, social, passkeys')
    await k.pause(1000)
    await k.scrollTo(page.getByText('Require a second factor everywhere'))
    await k.glide(await k.at(page.getByText('Require a second factor everywhere')), 800)
    k.cap('Second factor for everyone', 'Authenticator apps and passkeys')
    k.pop('MFA required', 'Environment-wide · orgs can add more')
    await k.pause(1700)
    await k.click(page.getByRole('link', { name: 'Password policy' }), 800)
    await page.getByText('Reject breached passwords').waitFor()
    k.cap('Passwords that hold up', 'Length, breach check, expiry and lockout')
    await k.glide(await k.at(page.getByText('Reject breached passwords')), 800)
    k.pop('Breached passwords blocked', 'Have I Been Pwned · k-anonymity')
    await k.pause(2000)
  },

  async keys(page, url, k) {
    await page.goto(envUrl(url, '/signing-keys'))
    await page.getByText('k-2026-10').waitFor()
    await page.mouse.move(1000, 250)
    await k.start()
    k.cap('Rotate signing keys', 'Publish first, activate later, retire last')
    await k.pause(900)
    await k.click(page.getByRole('button', { name: 'Create key' }), 800)
    await page.getByText('k-2026-11').first().waitFor()
    k.pop('New key published', 'k-2026-11 is in the JWKS, not yet signing')
    await k.pause(1500)
    await k.click(page.getByRole('button', { name: 'Actions for key k-2026-11' }), 700)
    await k.click(menuItem(page, 'Activate'), 450)
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    k.cap('Zero-downtime rotation', 'The old key keeps verifying until it retires')
    await k.pause(900)
    await k.click(dialog.getByRole('button', { name: 'Activate key' }), 600)
    await row(page, 'k-2026-11').getByText('Active').waitFor()
    k.pop('Key rotated', 'k-2026-10 is retiring')
    await k.pause(1800)
  },

  async activity(page, url, k) {
    await page.goto(envUrl(url, '/audit-events'))
    await page.getByText('Signed in').first().waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Every event, searchable', 'Sign-ins, failures, roles, provisioning')
    await k.pause(800)
    await k.click(page.getByLabel('Filter by event type'), 700)
    await k.type(page.getByLabel('Filter by event type'), 'login.failed', 80)
    await page.getByText('Sign-in failed').first().waitFor()
    await k.pause(600)
    k.pop('3 failed sign-ins', 'Same account, minutes apart')
    await k.pause(1500)
    k.cap('And every operator change', 'Policies, keys, webhooks and roles')
    await k.click(page.getByRole('button', { name: 'Change log' }), 800)
    await page.getByText('Password policy').first().waitFor()
    await k.glide({ x: 760, y: 300 }, 800)
    k.pop('Who changed what', 'Operator, target and time on every line')
    await k.pause(1800)
  },

  async webhooks(page, url, k) {
    await page.goto(envUrl(url, '/webhooks'))
    await page.getByText('Billing alerts').waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Stream events to your systems', 'Signed, ordered, retried with backoff')
    await k.pause(800)
    await k.glide(await k.at(page.getByText('Failing').first()), 800)
    k.pop('Failing', 'Billing alerts · 3 pending')
    await k.pause(1000)
    await k.click(row(page, 'Billing alerts').getByText('Billing alerts').first(), 500)
    await page.getByRole('button', { name: 'Send test event' }).waitFor()
    k.cap('Find the problem fast', 'Test the endpoint, read its deliveries')
    await k.pause(900)
    await k.click(page.getByRole('button', { name: 'Send test event' }), 800)
    await page.getByText('not delivered').first().waitFor()
    k.pop('HTTP 503', 'The endpoint is down, nothing is lost')
    await k.pause(1800)
  },

  async scim(page, url, k) {
    await page.goto(envUrl(url, '/provisioning'))
    await page.getByText('Okta · Acme').first().waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Directories provision users', 'SCIM 2.0 from Okta, Entra ID and Azure AD')
    await k.glide(await k.at(page.getByText('Okta · Acme').first()), 800)
    await k.pause(600)
    await k.glide(await k.at(page.getByText('Entra ID · Brightside').first()), 600)
    await k.pause(400)
    await k.glide(await k.at(page.getByText('Azure AD · Cobalt').first()), 600)
    k.pop('3 directories', 'Joiners and leavers, automatic')
    await k.pause(1800)
  },

  async orgs(page, url, k) {
    await page.goto(envUrl(url, '/organizations'))
    await page.getByText('Acme Logistics').waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('One tenant per customer', 'Each organization has its own people and rules')
    await k.glide(await k.at(page.getByText('Cobalt Energy').first()), 800)
    await k.pause(700)
    await k.click(row(page, 'Acme Logistics').getByText('Acme Logistics').first(), 700)
    await page.getByRole('heading', { name: 'Acme Logistics' }).waitFor()
    k.cap('Rules per organization', 'MFA and password policy, per customer')
    await k.glide(await k.at(page.getByText('Require a second factor').first()), 800)
    k.pop('MFA for Acme', 'Their rule, on top of yours')
    await k.pause(1500)
    await k.click(page.getByRole('link', { name: 'Members' }), 700)
    await page.getByText('Maya Chen').waitFor()
    k.cap('Their people, their groups', 'Members, groups and invitations')
    await k.pause(1500)
    await k.click(page.getByRole('link', { name: 'Groups' }), 600)
    await page.getByText('Finance').first().waitFor()
    await k.pause(1500)
  },

  async sso(page, url, k) {
    await page.goto(envUrl(url, '/organizations'))
    await page.getByText('Acme Logistics').waitFor()
    await k.click(row(page, 'Acme Logistics').getByText('Acme Logistics').first(), 10)
    await page.getByRole('link', { name: 'Domains' }).click()
    await page.getByText('acme.example').first().waitFor()
    await page.mouse.move(1000, 250)
    await k.start()
    k.cap('Prove the domain', 'Their email domain routes them to their IdP')
    await k.pause(800)
    await k.click(page.getByRole('button', { name: 'Verify acme.example' }), 800)
    await page.getByRole('button', { name: 'Verify acme.example' }).waitFor({ state: 'detached' })
    k.pop('Domain verified', 'acme.example · DNS TXT')
    await k.pause(1600)
    await k.click(page.getByRole('link', { name: 'SSO' }), 800)
    await page.getByText('Acme Okta').waitFor()
    k.cap('Per-company single sign-on', 'SAML, OIDC and LDAP, no code per customer')
    await k.glide(await k.at(page.getByText('Acme Okta')), 700)
    k.pop('Acme Okta', 'SAML · 612 linked users')
    await k.pause(2000)
  },

  async offboard(page, url, k) {
    await page.goto(envUrl(url, '/users'))
    await page.getByText('Liam Novak').waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Someone leaves the company', 'Offboarding should take seconds, not tickets')
    await k.glide(await k.at(page.getByText('Liam Novak').first()), 800)
    await k.pause(500)
    await k.click(row(page, 'Liam Novak').getByText('Liam Novak').first(), 300)
    await page.getByRole('button', { name: 'Suspend' }).waitFor()
    await k.pause(700)
    await k.scrollTo(page.getByRole('button', { name: 'Suspend' }))
    await k.click(page.getByRole('button', { name: 'Suspend' }), 800)
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    k.cap('One click cuts access everywhere', 'Sessions stop refreshing, tokens stop being issued')
    await k.pause(800)
    await k.click(dialog.getByRole('button', { name: 'Suspend' }), 600)
    await page.getByRole('button', { name: 'Reactivate' }).waitFor()
    k.pop('Access revoked', 'Liam Novak · every app, every device')
    await k.pause(1800)
  },

  async idp(page, url, k) {
    await page.goto(envUrl(url, '/federation'))
    await page.getByText('Acme Okta').first().waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Use the logins you already run', 'Google, Microsoft and GitHub for everyone')
    await k.glide(await k.at(page.getByText('Microsoft').first()), 800)
    await k.pause(600)
    k.cap('Each company, its own identity provider', 'Okta, Entra ID and Active Directory')
    await k.scrollTo(page.getByText('Acme Okta').first())
    await k.glide(await k.at(page.getByText('Brightside Entra ID').first()), 800)
    k.pop('SAML · OIDC · LDAP', 'Work emails go straight to their IdP')
    await k.pause(1500)
    await k.glide(await k.at(page.getByText('Cobalt Active Directory').first()), 700)
    await k.pause(1300)
  },

  async usage(page, url, k) {
    await page.goto(envUrl(url, '/usage'))
    await page.getByText('Daily usage').first().waitFor()
    await page.mouse.move(1000, 200)
    await k.start()
    k.cap('Know what it costs you', 'Users, organizations and applications vs limits')
    await k.glide(await k.at(page.getByText('12,480').first()), 800)
    await k.pause(800)
    await k.scrollTo(page.getByText('Daily usage').first())
    k.cap('Sign-ins, tokens and API calls', 'Per day, for 7, 30 or 90 days')
    k.pop('1.4M API requests', 'Last 30 days')
    await k.pause(2200)
  },
}
Object.assign(tomas, enterpriseTakes)
const takes = [
  ...Object.keys(enterpriseTakes).map(name => [name, enterpriseSim]),
  ['home'], ['apps'], ['role', liveSim], ['assign', liveSim], ['login'],
  ['users', liveSim], ['sessions', liveSim], ['policy'], ['keys', liveSim], ['activity', liveSim], ['webhooks', liveSim],
  ['scim'], ['orgs'], ['sso', liveSim], ['usage'], ['offboard', liveSim], ['idp'],
]

async function record() {
  buildConsole()
  const console_ = await startConsole()
  const browser = await chromium.launch()
  const meta = existsSync(path.join(work, 'takes.json')) && only ? JSON.parse(await readFile(path.join(work, 'takes.json'), 'utf8')) : {}
  if (!only) { await rm(path.join(work, 'frames'), { recursive: true, force: true }) }
  await mkdir(work, { recursive: true })
  const failures = []
  try {
    for (const [name, sim] of takes) {
      if (only && !only.includes(name)) continue
      const { context, page } = await openConsole(browser, { theme: 'dark', handle: sim?.() })
      await page.addInitScript(cursorScript)
      const k = take(page)
      try {
        await tomas[name](page, console_.url, k)
      } catch (e) {
        await page.screenshot({ path: path.join(work, `fail-${name}.png`) }).catch(() => {})
        console.error(`✗ take ${name} failed: ${e.message.split('\n')[0]} (screenshot: fail-${name}.png)`)
        failures.push(name)
        await context.close()
        continue
      }
      await k.stop()
      await context.close()
      // CDP only sends frames when something changes: resample to fixed FPS.
      const dir = path.join(work, 'frames', name)
      await rm(dir, { recursive: true, force: true })
      await mkdir(dir, { recursive: true })
      const frames = Math.ceil(k.log.duration * FPS)
      for (let f = 0, i = 0; f < frames; f++) {
        while (i + 1 < k.shots.length && k.shots[i + 1].at <= f / FPS) i++
        await writeFile(path.join(dir, `${String(f + 1).padStart(5, '0')}.jpg`), k.shots[i].data)
      }
      meta[name] = { ...k.log, fps: FPS, duration: frames / FPS }
      console.log(`· take ${name}: ${(frames / FPS).toFixed(1)} s, ${k.shots.length} real frames`)
    }
  } finally {
    await browser.close()
    console_.stop()
  }
  await writeFile(path.join(work, 'takes.json'), JSON.stringify(meta, null, 1))
  if (failures.length) throw new Error(`Recording failed: ${failures.join(', ')}; successful takes saved, render aborted`)
  return meta
}

// ── Storyboards: scenes in seconds, cuts on bars of the music (2.105 s) ──
// (track "Business Moves vol. 11": strong beats at 1.60, 3.70, 5.81, then every bar)
let meta = {}
const BAR = 2.105, START = 5.81
const slam = (from, to, words, extra = {}) => ({ type: 'slam', from, to, words, ...extra })
/** Builds the middle of a video: [clip, bars] pairs from START, one step number each. */
function clipsFrom(list, from = START) {
  let t = from
  return list.map(([clip], i) => {
    const c = meta[clip], start = Math.max(0, (c.cams[0]?.t ?? c.caps[0]?.t ?? 0) - .15)
    const bars = Math.max(3, Math.round((c.duration - start) / BAR))
    const s = { type: 'clip', clip, from: +t.toFixed(3), to: +(t + bars * BAR).toFixed(3), wipe: true, enter: i === 0, step: i + 1 }
    t += bars * BAR
    return s
  })
}
const frame = (opener, eyebrow, middle, closer, end) => {
  const clips = clipsFrom(middle)
  const t = clips.at(-1).to
  return [
    slam(0, 3.70, opener),
    slam(3.70, START, [{ text: 'Meet', at: .05 }, { text: 'IAMKit.', at: .5, mark: true }], { bg: 'accent', wipe: true, eyebrow }),
    ...clips,
    slam(t, t + BAR, closer, { wipe: true }),
    { type: 'end', from: t + BAR, to: t + BAR + 2 * BAR, bg: 'accent', wipe: true, eyebrow: 'IAMKit', ...end },
  ]
}
function enterpriseVideo() {
  let t = 0, step = 0
  const scenes = []
  for (const [title, subtitle, names] of [
    ['Identity for business.', 'Product walkthrough · fictional demo data', ['home', 'environments']],
    ['Applications & OAuth.', 'Register products and define their API access', ['register', 'apps', 'oauth', 'saml']],
    ['People & permissions.', 'Organizations, users and group-based roles', ['orgs', 'role', 'assign', 'groupRoles']],
    ['Your corporate directory.', 'SSO authenticates · SCIM provisions', ['providers', 'directory', 'sso']],
    ['Your sign-in experience.', 'Branded login, registration and authentication methods', ['login', 'signup']],
    ['Security & lifecycle.', 'Policies, session control and offboarding', ['policy', 'users', 'sessions', 'offboard', 'keys']],
    ['Operate with evidence.', 'Machines, integrations, activity and usage', ['machines', 'actions', 'webhooks', 'activity', 'usage']],
  ]) {
    scenes.push(slam(t, t + 6, [{ text: title, at: .2 }], { eyebrow: subtitle, wipe: true })); t += 6
    for (const clip of names) {
      if (!meta[clip]) throw new Error(`Missing enterprise take: ${clip}`)
      const duration = meta[clip].duration / .85
      scenes.push({ type: 'clip', clip, from: t, to: t + duration, speed: .85, full: true, step: ++step, wipe: true })
      t += duration
    }
  }
  scenes.push({ type: 'end', from: t, to: t + 8, bg: 'accent', eyebrow: 'IAMKit · Enterprise walkthrough', title: 'Identity, on your terms.', tagline: 'Self-hosted. Explicit access. Your brand.', cta: 'Explore the documentation' })
  return scenes
}
const makeVideos = () => ({
  ...(wanted?.includes('enterprise') ? { enterprise: enterpriseVideo() } : {}),
  // Platform / CTO: ship sign-in and access control without building them
  platform: frame(
    [{ text: 'Rented auth.', at: .1 }, { text: 'Guessed permissions.', at: .75 }, { text: 'Own it.', at: 1.6, mark: true }],
    'Self-hosted · Go + PostgreSQL',
    [['home', 3], ['apps', 5], ['role', 4], ['assign', 4], ['login', 4], ['webhooks', 4]],
    [{ text: 'A login isn’t a permission.', at: .05 }, { text: 'Now it’s explicit.', at: .55, mark: true }],
    { title: 'Identity, on your terms.', tagline: 'Self-hosted. Explicit by design.', cta: 'Read the docs' }),
  // Security / IT: control, evidence and rotation
  security: frame(
    [{ text: 'Who has access?', at: .1 }, { text: 'Who used it?', at: .75 }, { text: 'Prove it.', at: 1.6, mark: true }],
    'Self-hosted · your data stays yours',
    [['users', 5], ['sessions', 5], ['policy', 5], ['activity', 5], ['keys', 5]],
    [{ text: 'Not a promise.', at: .05 }, { text: 'An audit trail.', at: .55, mark: true }],
    { title: 'Identity you can audit.', tagline: 'Every login. Every session. Every change.', cta: 'Read the docs' }),
  // Corporate / enterprise IT: employees, their company logins and compliance
  corporate: frame(
    [{ text: 'Every new hire: a ticket.', at: .1 }, { text: 'Every exit: a risk.', at: .75 }, { text: 'Automate it.', at: 1.6, mark: true }],
    'Self-hosted · your company, your rules',
    [['idp', 4], ['scim', 4], ['policy', 5], ['offboard', 5], ['activity', 5]],
    [{ text: 'Joiners, movers, leavers.', at: .05 }, { text: 'Handled.', at: .55, mark: true }],
    { title: 'Workforce identity, solved.', tagline: 'Your IdP, your policies, your evidence.', cta: 'Read the docs' }),
  // Multi-tenant B2B SaaS: every customer is a tenant with its own SSO
  saas: frame(
    [{ text: 'One customer.', at: .1 }, { text: 'One identity provider.', at: .75 }, { text: 'Zero tickets.', at: 1.6, mark: true }],
    'Multi-tenant · SAML, OIDC, SCIM',
    [['orgs', 5], ['sso', 5], ['scim', 4], ['login', 4], ['usage', 4]],
    [{ text: 'Onboard the customer,', at: .05 }, { text: 'not a project.', at: .55, mark: true }],
    { title: 'Enterprise-ready on day one.', tagline: 'Per-customer SSO, SCIM and branding.', cta: 'Read the docs' }),
})

/** Fits each take to its scene: where it starts and how fast it runs. */
function plan(meta, storyboard) {
  const sfx = []
  const scenes = storyboard.map(s => {
    if (s.type !== 'clip') {
      for (const w of s.words ?? []) sfx.push({ file: 'slam', at: s.from + w.at, vol: .8 })
      if (s.type === 'end') sfx.push({ file: 'bell', at: s.from + .55, vol: .55 })
      return s
    }
    const clip = meta[s.clip], len = s.to - s.from
    if (!clip) throw new Error(`take ${s.clip} was not recorded`)
    const start = s.full ? 0 : Math.max(0, (clip.cams[0]?.t ?? clip.caps[0]?.t ?? 0) - .15)
    const speed = s.speed ?? Math.min(1.5, Math.max(.9, (clip.duration - start) / len))
    console.log(`  ${s.clip}: ${(clip.duration - start).toFixed(1)} s of take in ${len.toFixed(1)} s (x${speed.toFixed(2)})`)
    if ((clip.duration - start) / len > 1.5) console.warn(`! take ${s.clip} does not fit its scene: the end is cut`)
    const at = ct => s.from + (ct - start) / speed
    for (const c of clip.clicks) if (at(c) >= s.from && at(c) < s.to) sfx.push({ file: 'click', at: at(c), vol: .9 })
    const pops = clip.pops.map((p, i, all) => ({ at: at(p.t) - s.from, until: Math.min(len, (i + 1 < all.length ? Math.min(at(all[i + 1].t), at(p.t + (p.dur ?? 99))) : at(p.t + (p.dur ?? 99))) - s.from), text: p.text, label: p.label })).filter(p => p.at < len)
    for (const p of pops) sfx.push({ file: 'success', at: s.from + p.at, vol: .8 })
    const caps = clip.caps.map((c, i, all) => ({ at: at(c.t) - s.from, until: Math.min(len, i + 1 < all.length ? at(all[i + 1].t) - s.from : len), title: c.title, sub: c.sub })).filter(c => c.at < len)
    for (const c of caps) sfx.push({ file: 'tick', at: s.from + c.at, vol: .5 })
    return { ...s, in: start, speed, pops, caps }
  })
  return { scenes, sfx }
}

async function compose(meta, { scenes }, name, duration) {
  const browser = await chromium.launch()
  const page = await browser.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 1 })
  const types = { '.html': 'text/html', '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }
  const fontDir = p => path.join(site, 'node_modules/@fontsource-variable', p)
  const map = {
    '/stage.html': path.join(here, 'video/stage.html'),
    '/fonts/inter.woff2': fontDir('inter/files/inter-latin-wght-normal.woff2'),
    '/fonts/mono.woff2': fontDir('jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2'),
    '/brand/logo-ink.svg': path.join(here, 'video/brand/logo-ink.svg'),
  }
  await page.route('http://stage.local/**', async r => {
    const p = new URL(r.request().url()).pathname
    const file = map[p] ?? (p.startsWith('/frames/') ? path.join(work, p) : null)
    if (!file || !existsSync(file)) return r.fulfill({ status: 404, body: '' })
    return r.fulfill({ body: await readFile(file), contentType: types[path.extname(file)] })
  })
  await page.goto('http://stage.local/stage.html')
  await page.evaluate(s => window.setup(s), { scenes, clips: meta })

  const video = path.join(work, `video-${name}.mp4`)
  const enc = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-',
    '-c:v', 'libx264', '-preset', 'medium', '-crf', '12', '-pix_fmt', 'yuv420p', video], { stdio: ['pipe', 'inherit', 'inherit'] })
  const done = new Promise((ok, bad) => enc.on('exit', c => c === 0 ? ok() : bad(new Error(`ffmpeg ${c}`))))
  const total = Math.round(duration * FPS)
  for (let f = 0; f < total; f++) {
    await page.evaluate(t => window.render(t), f / FPS)
    const jpg = await page.screenshot({ type: 'jpeg', quality: 95 })
    if (!enc.stdin.write(jpg)) await new Promise(r => enc.stdin.once('drain', r))
    if (f % 300 === 0) console.log(`· ${name} frame ${f}/${total}`)
  }
  enc.stdin.end()
  await done
  // Stills for review: two per scene.
  for (const s of scenes) for (const k of [.3, .75]) {
    const t = +(s.from + (s.to - s.from) * k).toFixed(2)
    await page.evaluate(t => window.render(t), t)
    await page.screenshot({ path: path.join(work, 'stills', `${name}-${String(t).padStart(5, '0')}.png`) })
  }
  await browser.close()
  return video
}

/** Music with soft in/out, effects at their instant, limiter at the end. */
function mix(sfx, name, duration) {
  const audio = path.join(here, 'video/audio')
  // Loop the licensed soundtrack so long walkthroughs are never cut to its length.
  const varied = name === 'enterprise' && process.argv.includes('--audio-only')
  const inputs = varied
    ? ['clean-soul', 'floating-cities', 'dreams-become-real'].flatMap(n => ['-i', path.join(audio, `${n}.mp3`)])
    : ['-stream_loop', '-1', '-i', path.join(audio, 'music.mp3')]
  // Track changes straddle the directory and security chapter cards. No loops.
  const parts = varied ? [
    '[0:a]atrim=0:158.372549,asetpts=PTS-STARTPTS,loudnorm=I=-25:TP=-3:LRA=9,aresample=44100,afade=t=in:d=3[a0]',
    '[1:a]atrim=0:86.509804,asetpts=PTS-STARTPTS,loudnorm=I=-25:TP=-3:LRA=9,aresample=44100[a1]',
    `[2:a]atrim=0:${duration - 232.882353},asetpts=PTS-STARTPTS,loudnorm=I=-25:TP=-3:LRA=9,aresample=44100[a2]`,
    '[a0][a1]acrossfade=d=6:c1=qsin:c2=qsin[a01]',
    `[a01][a2]acrossfade=d=6:c1=qsin:c2=qsin,afade=t=out:st=${duration - 5}:d=5,volume='if(between(t,27.3,29.3)+between(t,97,99)+between(t,203.9,205.9)+between(t,294.7,296.7),0.35,1)':eval=frame[m]`,
  ] : [`[0]atrim=0:${duration},afade=t=in:d=0.15,afade=t=out:st=${duration - 2.2}:d=2.2,volume=0.55[m]`]
  sfx.forEach((s, i) => {
    inputs.push('-i', path.join(audio, `${s.file}.ogg`))
    const ms = Math.max(0, Math.round(s.at * 1000))
    parts.push(`[${i + (varied ? 3 : 1)}]aresample=44100,adelay=${ms}|${ms},volume=${s.vol * (varied ? .65 : 1)}[s${i}]`)
  })
  parts.push(`[m]${sfx.map((_, i) => `[s${i}]`).join('')}amix=inputs=${sfx.length + 1}:normalize=0:duration=first,alimiter=limit=0.9[a]`)
  const wav = path.join(work, `audio-${name}.wav`)
  ff(...inputs, '-filter_complex', parts.join(';'), '-map', '[a]', '-ac', '2', wav)
  return wav
}

const takesFile = path.join(work, 'takes.json')
meta = reuse && existsSync(takesFile) && !only ? JSON.parse(await readFile(takesFile, 'utf8')) : await record()
const videos = makeVideos()
await mkdir(path.join(work, 'stills'), { recursive: true })
await mkdir(out, { recursive: true })
for (const [name, storyboard] of Object.entries(videos)) {
  if (wanted && !wanted.includes(name)) continue
  const duration = storyboard.at(-1).to
  console.log(`▶ ${name} (${duration.toFixed(1)} s)`)
  const cut = plan(meta, storyboard)
  await writeFile(path.join(out, `iamkit-${name}.chapters.json`), JSON.stringify(storyboard.filter(s => s.type !== 'clip').map(s => ({ start: s.from, title: s.words?.map(w => w.text).join(' ') ?? s.title })), null, 2))
  if (process.argv.includes('--takes-only')) continue
  if (process.argv.includes('--audio-only')) {
    if (name !== 'enterprise') throw new Error('--audio-only requires --video enterprise')
    const audio = mix(cut.sfx, name, duration)
    const credit = 'Clean Soul; Floating Cities; Dreams Become Real — Kevin MacLeod (incompetech.com), CC BY 4.0 https://creativecommons.org/licenses/by/4.0/; excerpts, fades and mix. SFX: Kenney CC0.'
    for (const ext of ['mp4', 'webm']) {
      const target = path.join(out, `iamkit-${name}-music-v2.${ext}`)
      ff('-i', path.join(out, `iamkit-${name}.${ext}`), '-i', audio, '-map', '0:v:0', '-map', '1:a:0', '-c:v', 'copy', '-c:a', ext === 'mp4' ? 'aac' : 'libopus', '-b:a', '160k', '-metadata', `comment=${credit}`, '-shortest', ...(ext === 'mp4' ? ['-movflags', '+faststart'] : []), target)
      console.log('✓', target)
    }
    continue
  }
  const video = await compose(meta, cut, name, duration)
  const audio = mix(cut.sfx, name, duration)
  const base = path.join(out, `iamkit-${name}`)
  ff('-i', video, '-i', audio, '-c:v', 'libx264', '-preset', 'slow', '-crf', '20', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '160k', '-shortest', '-movflags', '+faststart', `${base}.mp4`)
  ff('-i', video, '-i', audio, '-c:v', 'libvpx-vp9', '-crf', '33', '-b:v', '0', '-row-mt', '1', '-c:a', 'libopus', '-b:a', '128k', '-shortest', `${base}.webm`)
  ff('-ss', String(storyboard.find(s => s.type === 'clip').from + 3), '-i', video, '-frames:v', '1', '-q:v', '3', `${base}.jpg`)
  console.log('✓', path.relative(process.cwd(), `${base}.mp4`), `(${duration.toFixed(1)} s)`)
}
