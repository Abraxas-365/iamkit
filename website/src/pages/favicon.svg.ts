import mark from '../../../docs/assets/iamkit-mark.svg?raw'
import type { APIRoute } from 'astro'

// Serve the source brand mark rather than maintaining another copy.
export const GET: APIRoute = () => new Response(
  mark,
  { headers: { 'Content-Type': 'image/svg+xml' } },
)
