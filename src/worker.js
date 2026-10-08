// SiteCheck NZ — serves the static site and locks paid checklists after the free period.
// LOCK variable (Cloudflare dashboard or wrangler.jsonc): "auto" (default) locks from LOCK_FROM,
// "on" locks now, "off" opens everything.
const LOCK_FROM = Date.parse('2026-10-12T11:00:00Z'); // 12:00am Tue 13 Oct 2026, NZDT
const FREE = new Set(['framing']);
const PAID = new Set(['prepour', 'floor-slab', 'cladding', 'preline', 'membrane', 'drainage',
  'pd-final', 'final-inspection', 'retaining-wall', 'record-of-work']);

function locked(env) {
  const mode = (env.LOCK || 'auto').toLowerCase();
  if (mode === 'off') return false;
  if (mode === 'on') return true;
  return Date.now() >= LOCK_FROM;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/status') {
      return new Response(JSON.stringify({ locked: locked(env), free: [...FREE], lockFrom: LOCK_FROM }),
        { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
    }
    const m = url.pathname.match(/^\/([a-z-]+?)(\.html)?$/);
    if (m && PAID.has(m[1]) && locked(env)) {
      return Response.redirect(url.origin + '/access.html?stage=' + m[1], 302);
    }
    return env.ASSETS.fetch(request);
  }
};
