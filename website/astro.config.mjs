import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import { unified } from '@astrojs/markdown-remark'
import { remarkDocs } from './scripts/docs.mjs'
import { sidebar } from './src/sidebar.mjs'

export default defineConfig({
  // Add the public site URL when a domain is selected; no invented canonical URL.
  trailingSlash: 'always',
  markdown: { processor: unified({ remarkPlugins: [remarkDocs] }) },
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
