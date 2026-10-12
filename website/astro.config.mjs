import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import { unified } from '@astrojs/markdown-remark'
import { remarkDocs } from './scripts/docs.mjs'
import { sidebar } from './src/sidebar.mjs'

const base = `/${(process.env.SITE_BASE_PATH ?? '').replace(/^\/+|\/+$/g, '')}/`.replace('//', '/')

export default defineConfig({
  // Pages supplies these at build time; local development still runs at /.
  site: process.env.SITE_URL || undefined,
  base,
  trailingSlash: 'always',
  markdown: { processor: unified({ remarkPlugins: [[remarkDocs, { base }]] }) },
  integrations: [starlight({
    title: 'IAMKit',
    description: 'Self-hosted identity and tenant-aware authorization. Integration guides, API references and operations documentation.',
    logo: { src: '../docs/assets/iamkit-mark.svg' },
    social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/Abraxas-365/iamkit' }],
    customCss: ['./src/styles/theme.css'],
    expressiveCode: { themes: ['github-dark', 'github-light'], styleOverrides: { borderRadius: '0.25rem' } },
    sidebar,
  })],
})
