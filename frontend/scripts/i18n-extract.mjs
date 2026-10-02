// Regenerates src/locales/en.json from the t()/rich() calls in src (npm run
// i18n), and reports keys other catalogs lack or no longer use. Keys are
// the English text; a call with a `count` value gets i18next plural keys
// (`_one`, `_other`). en.json is written, other catalogs only checked:
// translators fill them, and src/locales.test.ts fails on gaps.
//
//   node scripts/i18n-extract.mjs          write en.json, report gaps
//   node scripts/i18n-extract.mjs --check  fail if en.json is stale
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src')
const locales = path.join(root, 'locales')
const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
  const file = path.join(dir, entry.name)
  if (entry.isDirectory()) return entry.name === 'locales' ? [] : walk(file)
  return /\.tsx?$/.test(entry.name) && !/\.test\.tsx?$|\.d\.ts$/.test(entry.name) ? [file] : []
})

/** extract returns the catalog keys used in src: singular keys map to
 * themselves, plural ones to their `_one`/`_other` forms. */
export function extract() {
  const keys = new Map()
  const problems = []
  for (const file of walk(root)) {
    const source = fs.readFileSync(file, 'utf8')
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
    const visit = node => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && (node.expression.text === 't' || node.expression.text === 'rich') && node.arguments.length) {
        const [key, values] = node.arguments
        const where = `${path.relative(root, file)}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`
        if (!ts.isStringLiteral(key) && !ts.isNoSubstitutionTemplateLiteral(key)) problems.push(`${where}: ${node.expression.text}() needs a literal key`)
        else {
          const plural = values && ts.isObjectLiteralExpression(values) && values.properties.some(p => p.name?.getText(sf) === 'count')
          if (plural) for (const form of ['one', 'other']) keys.set(`${key.text}_${form}`, key.text)
          else keys.set(key.text, key.text)
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(sf)
  }
  return { keys, problems }
}

const sorted = map => Object.fromEntries([...map].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { keys, problems } = extract()
  for (const p of problems) console.error(p)
  const enFile = path.join(locales, 'en.json')
  const previous = JSON.parse(fs.readFileSync(enFile, 'utf8'))
  // English plural forms keep their wording (e.g. "1 result" for `_one`).
  const en = sorted(new Map([...keys].map(([k, text]) => [k, k.endsWith('_one') && previous[k] ? previous[k] : text])))
  const body = JSON.stringify(en, null, 2) + '\n'
  if (process.argv.includes('--check')) {
    if (fs.readFileSync(enFile, 'utf8') !== body) { console.error('src/locales/en.json is stale: run npm run i18n'); process.exit(1) }
  } else fs.writeFileSync(enFile, body)
  for (const name of fs.readdirSync(locales).filter(f => f.endsWith('.json') && f !== 'en.json')) {
    const catalog = JSON.parse(fs.readFileSync(path.join(locales, name), 'utf8'))
    const missing = Object.keys(en).filter(k => !(k in catalog))
    const unused = Object.keys(catalog).filter(k => !(k in en) && !(/_(zero|two|few|many)$/.test(k) && `${k.replace(/_(zero|two|few|many)$/, '')}_other` in en))
    console.log(`${name}: ${Object.keys(en).length - missing.length}/${Object.keys(en).length} keys, ${missing.length} missing, ${unused.length} unused`)
  }
  if (problems.length) process.exit(1)
}
