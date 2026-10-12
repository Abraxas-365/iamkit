import { test } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { docId, docsRoot, metadata, resolveLink, repository, allSlugs, sidebarSlugs } from './docs.mjs'

const overview = path.join(docsRoot, 'start/overview.md')
test('routes preserve directories and collapse README/index', () => {
  assert.equal(docId('index.md'), 'docs')
  assert.equal(docId('examples/README.md'), 'docs/examples')
  assert.equal(docId('reference/api/index.md'), 'docs/reference/api')
  assert.equal(docId('start/overview.md'), 'docs/start/overview')
})
test('metadata comes from source Markdown and edit link points to source', () => {
  const data = metadata(overview)
  assert.equal(data.title, 'What IAMKit does')
  assert.match(data.description, /^IAMKit is a self-hosted/)
  assert.equal(data.editUrl, `${repository}/edit/main/docs/start/overview.md`)
})
test('rewrites document links while preserving anchors and external URLs', () => {
  assert.equal(resolveLink('../concepts/authorization.md#permissions', overview), '/docs/concepts/authorization/#permissions')
  assert.equal(resolveLink('../concepts/authorization.md?view=full#permissions', overview), '/docs/concepts/authorization/?view=full#permissions')
  assert.equal(resolveLink('#choose-your-integration', overview), '#choose-your-integration')
  assert.equal(resolveLink('https://example.com/a.md', overview), 'https://example.com/a.md')
  assert.equal(resolveLink('../../README.md#provenance--license', overview), `${repository}/blob/main/README.md#provenance--license`)
  assert.equal(resolveLink('../examples/', overview), `${repository}/tree/main/docs/examples`)
})
test('project-site links include the base without changing fragments or GitHub targets', () => {
  assert.equal(resolveLink('../concepts/authorization.md?view=full#permissions', overview, '/iamkit/'), '/iamkit/docs/concepts/authorization/?view=full#permissions')
  assert.equal(resolveLink('../index.md', overview, '/iamkit/'), '/iamkit/docs/')
  assert.equal(resolveLink('#choose-your-integration', overview, '/iamkit/'), '#choose-your-integration')
  assert.equal(resolveLink('https://example.com/a.md', overview, '/iamkit/'), 'https://example.com/a.md')
  assert.equal(resolveLink('../../README.md', overview, '/iamkit/'), `${repository}/blob/main/README.md`)
})
test('curated sidebar lists every document exactly once', async () => {
  const { sidebar } = await import('../src/sidebar.mjs')
  const listed = sidebarSlugs(sidebar)
  assert.deepEqual([...new Set(listed)].sort(), allSlugs().sort())
  assert.equal(listed.length, new Set(listed).size, 'a document appears twice in the sidebar')
})
test('navigation separates SDKs from the API and exposes product entry points', async () => {
  const { sidebar } = await import('../src/sidebar.mjs')
  const labels = sidebar.filter(item => item.items).map(item => item.label)
  assert.deepEqual(labels.slice(0, 6), [
    'Get started', 'Integrate your application', 'Authentication',
    'Enterprise connections', 'Users and organizations', 'Authorization',
  ])
  const sdks = sidebar.find(item => item.label === 'SDKs and tools')
  for (const slug of ['docs/reference/sdk', 'docs/reference/sdk/node', 'docs/reference/sdk/python', 'docs/reference/sdk/react-widgets']) {
    assert.ok(sidebarSlugs(sdks.items).includes(slug), `SDK not discoverable: ${slug}`)
  }
  for (const source of ['sign-in', 'enterprise', 'organizations', 'authorization', 'platform']) {
    const hub = path.join(docsRoot, 'guides', source, 'index.md')
    assert.ok(metadata(hub).description.length > 0, `missing hub introduction: ${source}`)
  }
})
test('fails on missing source files rather than publishing broken links', () => {
  assert.throws(() => resolveLink('../missing.md', overview), /Broken source link/)
})
