import { expect, it } from 'vitest'
import { describeUserAgent } from './user-agent'

it('names browser and system', () => {
  expect(describeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15')).toBe('Safari 17 · macOS')
  expect(describeUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.51')).toBe('Edge 124 · Windows')
  expect(describeUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0')).toBe('Firefox 125 · Linux')
  expect(describeUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1')).toBe('Safari 17 · iOS')
  expect(describeUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36')).toBe('Chrome 124 · Android')
})

it('falls back to the truncated raw agent', () => {
  expect(describeUserAgent('curl/8.4.0')).toBe('curl/8.4.0')
  expect(describeUserAgent('x'.repeat(100), 10)).toBe('xxxxxxxxx…')
  expect(describeUserAgent(null)).toBe('')
  expect(describeUserAgent('  ')).toBe('')
})
