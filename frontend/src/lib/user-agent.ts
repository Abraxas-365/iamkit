// describeUserAgent reduces a User-Agent to "Browser on OS" for the session
// lists. It is deliberately small: the common browsers and systems only; any
// other agent comes back as its raw text cut to `max` characters, and an
// empty one as ''.
const browsers: [RegExp, string][] = [
  [/\b(?:Edg|EdgA|EdgiOS)\/(\d+)/, 'Edge'], [/\bOPR\/(\d+)/, 'Opera'], [/\b(?:Firefox|FxiOS)\/(\d+)/, 'Firefox'],
  [/\b(?:Chrome|CriOS)\/(\d+)/, 'Chrome'], [/\bVersion\/(\d+)[\d.]* (?:Mobile\/\S+ )?Safari\//, 'Safari'],
]
const systems: [RegExp, string][] = [
  [/\b(?:iPhone|iPad|iPod)\b/, 'iOS'], [/\bAndroid\b/, 'Android'], [/\bWindows\b/, 'Windows'],
  [/\bMac OS X\b|\bMacintosh\b/, 'macOS'], [/\bCrOS\b/, 'ChromeOS'], [/\bLinux\b|\bX11\b/, 'Linux'],
]

export function describeUserAgent(agent: string | null | undefined, max = 40): string {
  const raw = (agent ?? '').trim()
  if (!raw) return ''
  const browser = browsers.map(([re, name]) => ({ name, match: re.exec(raw) })).find(b => b.match)
  const system = systems.find(([re]) => re.test(raw))?.[1]
  if (browser && system) return `${browser.name} ${browser.match![1]} · ${system}`
  if (browser) return `${browser.name} ${browser.match![1]}`
  return raw.length > max ? `${raw.slice(0, max - 1)}…` : raw
}
