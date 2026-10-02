// Narrow-width check of hosted pages in every language.
// Usage: IAMKIT_TEST_E2E=1 IAMKIT_LANGUAGE_SNAPSHOTS=<dir> go test -run TestHostedEveryLanguage ./tests/e2e
//        node scripts/check_hosted_languages.js <dir> [screenshot-dir]
// Fails when any element overflows the page horizontally at 320 px.
const fs = require('fs')
const path = require('path')
const { chromium } = require('playwright')

const dir = process.argv[2]
const shots = process.argv[3]
if (!dir) { console.error('usage: check_hosted_languages.js <snapshot-dir> [screenshot-dir]'); process.exit(2) }

;(async () => {
  const browser = await chromium.launch({ headless: true })
  const page = await browser.newPage({ viewport: { width: 320, height: 640 } })
  const problems = []
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.html')).sort()
  for (const file of files) {
    await page.setContent(fs.readFileSync(path.join(dir, file), 'utf8'), { waitUntil: 'load' })
    const overflow = await page.evaluate(() => {
      const width = document.documentElement.clientWidth
      const out = []
      if (document.documentElement.scrollWidth > width + 1) out.push(`document ${document.documentElement.scrollWidth}px`)
      for (const el of document.querySelectorAll('main *')) {
        const r = el.getBoundingClientRect()
        if (r.width && (r.right > width + 1 || r.left < -1)) out.push(`${el.tagName.toLowerCase()}${el.className ? '.' + el.className : ''} [${Math.round(r.left)},${Math.round(r.right)}] "${(el.textContent || '').trim().slice(0, 40)}"`)
      }
      return out.slice(0, 5)
    })
    if (overflow.length) problems.push(`${file}: ${overflow.join('; ')}`)
    if (shots) await page.screenshot({ path: path.join(shots, file.replace(/\.html$/, '.png')), fullPage: true })
  }
  await browser.close()
  console.log(`${files.length} pages checked at 320px`)
  if (problems.length) { console.log(problems.join('\n')); process.exit(1) }
})()
