# IAMKit website

Static landing page and documentation built with Astro + Starlight. Requires Node
22.12+ and npm. Run from a checkout of the whole repository:

```sh
cd website
npm ci
npm run dev
```

Open <http://127.0.0.1:4321/> for the landing page and `/docs/` for documentation.
For the production build, including Pagefind
search, use `npm run build && npm run preview`. Preview serves the last build;
rebuild after changes. Development mode does not provide the production search index.

## Content and styling

- `../docs/**/*.md` is the only documentation source. No generated Markdown,
  copies or front matter migration. The loader derives titles and descriptions;
  the remark adapter removes the duplicate H1 and rewrites local Markdown links.
- Documentation lives under `/docs/`. `src/pages/index.astro` is the custom
  landing page at `/`, styled with `src/styles/landing.css` and the same shared
  tokens. Its theme toggle persists the same preference as Starlight.
- Repository files outside the documentation, source examples and downloads
  link to GitHub. Existing SVG images are bundled from `docs/assets/`.
- `frontend/src/theme.css` owns the shared colors, fonts and radius. The console
  imports it directly; `src/styles/theme.css` maps it to Starlight's variables.
  This does not import the console application, Tailwind or its React components.
- The sidebar is curated in `src/sidebar.mjs` (reading order, nested groups).
  Titles come from each page's H1. `npm test` fails when a document under
  `../docs` is missing from the sidebar or listed twice, so add new pages there.
  Folder layout: `start`, `concepts`, `guides/<topic>`, `reference`,
  `operations`, `examples`, `contributing`.
- Only the existing English content is included. Dark/light/auto selection uses
  Starlight's accessible theme control. The existing integration SVG stays dark
  in either theme; it is not a newly generated theme-aware illustration.

## Validation

```sh
npm test
npm run check
npm run build
npm run check:links
```

`check:links` checks rendered local links, anchors and assets, not remote URLs.
From the repository root also run `python3 scripts/check_docs.py`. Shared theme
changes should pass the console's build, lint and tests.

No production domain or deployment is configured. The build skips sitemap
creation until `site` is set; Starlight also logs warnings for its empty optional
i18n collection and default 404 fallback. An API explorer, translations and
publishing workflow are not included. The landing combines actual product captures
with explicitly conceptual architecture/federation diagrams; it makes no
unverified performance or certification claims.

## Product captures

`src/assets/` contains real console captures (roles, organization settings and
hosted-login configuration) from a local supplier-portal demo. Captures have
light/dark variants at 3× density (4320 × 2820); Astro generates responsive WebP
images at quality 100, including 2×/3× candidates for Retina screens. Cropped
previews request enough pixels for the enlarged image, not just its container.
The page identifies these as demonstration data, not customer endorsements.
The branding editor includes its actual server-rendered sample preview.

Refresh captures against a local demo installation with read-only access. Do not
include credentials, real customer identities or production data. Wait for data,
fonts and theme transitions before capturing; check each image before publishing.
The console preview opens the full-size capture, not an administrative session.

## Launch videos

`npm run videos` records one pool of takes of the console (mocked API, fictional "Northwind Cloud"
data, `scripts/demo-extra.mjs`) with Playwright, composes `scripts/video/stage.html` and writes four
videos, one per buyer: `public/videos/iamkit-{platform,security,corporate,saas}.{mp4,webm,jpg}`
(`--reuse` recomposes without re-recording, `--only users,keys` re-records those takes,
`--video security` composes just one). Needs `ffmpeg` and a Playwright Chromium.
Music: "Business Moves" by ende.app (CC BY 4.0); sound effects by Kenney (CC0).

### Full enterprise walkthrough

`npm run videos -- --reuse --video enterprise` composes the long-form walkthrough
from recorded takes, at 0.85× playback with seven chapter cards. Output:
`public/videos/iamkit-enterprise.{mp4,webm,jpg}` and `.chapters.json`.
Record its additional workflows with `--only environments,register,oauth,groupRoles,signup,providers,directory,machines,actions,saml --takes-only`, then compose.
Music loops to cover the complete demonstration; no take is cut to fit the song.

For the revised, non-looping soundtrack run
`npm run videos -- --reuse --video enterprise --audio-only`.
This copies the original MP4/WebM video streams unchanged and writes separate
`iamkit-enterprise-music-v2.{mp4,webm}` files. Three Kevin MacLeod tracks
(Clean Soul, Floating Cities, Dreams Become Real; CC BY 4.0) transition across
the directory and security chapters, with quieter music and reduced effects.
Publish with `public/videos/iamkit-enterprise-music-v2-credits.txt`; attribution
is also embedded in the media metadata. Original videos remain untouched.

The real console runs against fictional, stateful API responses. SSO configuration
for Entra ID / Google Workspace is distinct from inbound SCIM provisioning; the
video does not perform a live directory sync or an external provider login.
Environment separation is shown, not cloning, promotion or a built-in test runner.
SAML IdP requires the deployment feature to be enabled. Preserve the music credit
when publishing; no real customer data or credentials appear in the recordings.

