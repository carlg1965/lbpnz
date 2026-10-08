// SiteCheck NZ — static site + paid access.
//
// Settings (Cloudflare → Workers & Pages → lbpnz → Settings → Variables and secrets):
//   LOCK               "auto" (default) locks paid pages from LOCK_FROM, "on" locks now, "off" opens everything.
//   STRIPE_SECRET_KEY  Stripe secret key (sk_test_… while testing, sk_live_… when live). Add as a Secret.
//   ACCESS_SECRET      Any long random string, used to sign access passes. Add as a Secret. Never share it.
//   STUDENT_CODE       Code you give students so they can buy the student plan. Add as a Secret.
//
// Passes are signed cookies valid for 12 months; nothing about the customer is stored here.

const LOCK_FROM = Date.parse('2026-10-12T11:00:00Z'); // 12:00am Tue 13 Oct 2026, NZDT
const FREE = new Set(['framing']);
const PAID = new Set(['prepour', 'floor-slab', 'cladding', 'preline', 'membrane', 'drainage',
  'pd-final', 'final-inspection', 'retaining-wall', 'record-of-work']);
const PLANS = {
  student: { name: 'SiteCheck NZ — Student (12 months)', cents: 3900 },
  pro:     { name: 'SiteCheck NZ — LBP Pro (12 months)', cents: 14900 },
};
const COOKIE = 'sc_access';
const PASS_DAYS = 365;

function locked(env) {
  const mode = (env.LOCK || 'auto').toLowerCase();
  if (mode === 'off') return false;
  if (mode === 'on') return true;
  return Date.now() >= LOCK_FROM;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/api/status') return status(request, env);
    if (path === '/api/checkout') return checkout(request, url, env);
    if (path === '/api/success') return success(url, env);
    if (path === '/api/unlock') return unlock(url, env);

    const m = path.match(/^\/([a-z-]+?)(\.html)?$/);
    if (m && PAID.has(m[1]) && locked(env) && !(await readPass(request, env))) {
      return Response.redirect(url.origin + '/access.html?stage=' + m[1], 302);
    }
    return env.ASSETS.fetch(request);
  },
};

async function status(request, env) {
  const pass = await readPass(request, env);
  return json({ locked: locked(env), free: [...FREE], lockFrom: LOCK_FROM,
    pass: pass ? { plan: pass.p, expires: pass.e } : null, payments: !!(env.STRIPE_SECRET_KEY && env.ACCESS_SECRET) });
}

/* ---------- Stripe ---------- */
async function stripe(env, method, endpoint, params) {
  const res = await fetch('https://api.stripe.com/v1/' + endpoint, {
    method,
    headers: { Authorization: 'Bearer ' + env.STRIPE_SECRET_KEY, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params ? new URLSearchParams(params) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error((data.error && data.error.message) || 'Stripe error');
  return data;
}

async function checkout(request, url, env) {
  const plan = url.searchParams.get('plan');
  const back = url.origin + '/access.html';
  if (!PLANS[plan]) return text('Unknown plan', 400);
  if (!env.STRIPE_SECRET_KEY || !env.ACCESS_SECRET) return text('Payments are not set up yet.', 503);
  if (plan === 'student') {
    const code = (url.searchParams.get('code') || '').trim().toLowerCase();
    if (!env.STUDENT_CODE || code !== String(env.STUDENT_CODE).trim().toLowerCase())
      return Response.redirect(back + '?err=code', 302);
  }
  try {
    const s = await stripe(env, 'POST', 'checkout/sessions', {
      mode: 'payment',
      'line_items[0][quantity]': '1',
      'line_items[0][price_data][currency]': 'nzd',
      'line_items[0][price_data][unit_amount]': String(PLANS[plan].cents),
      'line_items[0][price_data][product_data][name]': PLANS[plan].name,
      'metadata[plan]': plan,
      'invoice_creation[enabled]': 'true',
      success_url: url.origin + '/api/success?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: back,
    });
    return Response.redirect(s.url, 303);
  } catch (e) { return text('Sorry, the payment page could not be opened: ' + e.message, 502); }
}

async function success(url, env) {
  const id = url.searchParams.get('session_id') || '';
  if (!/^cs_[A-Za-z0-9_]+$/.test(id)) return text('Missing payment reference', 400);
  let s;
  try { s = await stripe(env, 'GET', 'checkout/sessions/' + encodeURIComponent(id)); }
  catch (e) { return text('Sorry, the payment could not be confirmed: ' + e.message, 502); }
  if (s.payment_status !== 'paid') return text('This payment has not been completed.', 402);
  const plan = s.metadata && s.metadata.plan;
  if (!PLANS[plan]) return text('Unknown plan on this payment', 400);
  // Expiry is fixed from the payment time, so reloading this link never extends it.
  const token = await sign({ p: plan, e: s.created * 1000 + PASS_DAYS * 864e5 }, env);
  return withPass(url.origin + '/access.html?paid=' + plan + '&key=' + encodeURIComponent(token), token);
}

async function unlock(url, env) {
  const p = await verify(url.searchParams.get('key') || '', env);
  if (!p) return text('This unlock link is not valid or has expired.', 400);
  return withPass(url.origin + '/', url.searchParams.get('key'));
}

/* ---------- Passes ---------- */
function withPass(dest, token) {
  return new Response(null, { status: 302, headers: {
    Location: dest, 'Cache-Control': 'no-store',
    'Set-Cookie': COOKIE + '=' + token + '; Path=/; Max-Age=' + PASS_DAYS * 86400 + '; Secure; HttpOnly; SameSite=Lax' } });
}
async function readPass(request, env) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|;\\s*)' + COOKIE + '=([^;]+)'));
  return m ? verify(m[1], env) : null;
}
const enc = new TextEncoder();
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const hkey = env => crypto.subtle.importKey('raw', enc.encode(env.ACCESS_SECRET || ''), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
async function sign(payload, env) {
  const body = b64u(enc.encode(JSON.stringify(payload)));
  return body + '.' + b64u(await crypto.subtle.sign('HMAC', await hkey(env), enc.encode(body)));
}
async function verify(token, env) {
  if (!env.ACCESS_SECRET) return null;
  const [body, sig] = String(token).split('.');
  if (!body || !sig) return null;
  try {
    if (!(await crypto.subtle.verify('HMAC', await hkey(env), unb64u(sig), enc.encode(body)))) return null;
    const p = JSON.parse(new TextDecoder().decode(unb64u(body)));
    return p && PLANS[p.p] && p.e > Date.now() ? p : null;
  } catch (e) { return null; }
}
const json = o => new Response(JSON.stringify(o), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const text = (m, s) => new Response(m, { status: s, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' } });
