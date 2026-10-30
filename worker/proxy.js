// Cloudflare Worker: Roblox用プロキシ(v2)
//
//   GET  /health            → { ok, hasApiKey }   接続確認(キーの値は返さない)
//   GET  /asset/{id}        → アセット本体(Open Cloud Asset Delivery をAPIキーで呼び、CDNから取得して返す)
//   GET|POST /?url=<URL>    → users / avatar などの公開API用の中継(APIキーは付けない)
//
// 設定:
//   ROBLOX_API_KEY  (シークレット)  Open CloudのAPIキー。コードやwrangler.tomlには書かない。
//                                  npx wrangler secret put ROBLOX_API_KEY  /  ダッシュボードの「変数とシークレット」
//   ALLOWED_ORIGIN  (変数・任意)    例: https://your-site.pages.dev  設定すると、そのOriginのリクエストだけ受け付ける。
//
// 背景: 2025-04-02以降、Asset Deliveryは認証なしだと401を返すため、アセット取得にはAPIキーが必要。

const ALLOWED_HOSTS = [/(^|\.)roblox\.com$/, /(^|\.)rbxcdn\.com$/];
const ASSET_API = 'https://apis.roblox.com/asset-delivery-api/v1/assetId/';
const ASSET_PATH = /^\/asset\/(\d{1,19})$/;

function corsHeaders(env, req) {
  const origin = (env && env.ALLOWED_ORIGIN) || '*';
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': req.headers.get('Access-Control-Request-Headers') || 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

const json = (obj, status, cors) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json' } });

// ALLOWED_ORIGIN が設定されている場合、Originが一致しないリクエスト(Origin無しも含む)を拒否する。
// ※ブラウザ以外はOriginを偽装できるため、これは「うっかり利用」を防ぐ程度の保護。
function originOk(env, req) {
  const allowed = env && env.ALLOWED_ORIGIN;
  if (!allowed || allowed === '*') return true;
  return req.headers.get('Origin') === allowed;
}

const allowedHost = (u) => u.protocol === 'https:' && ALLOWED_HOSTS.some((re) => re.test(u.hostname));

async function handleAsset(id, env, req, ctx, cors) {
  if (!env || !env.ROBLOX_API_KEY) return json({ error: 'NO_API_KEY' }, 503, cors);

  // エッジキャッシュ(ヒットすればRoblox APIを呼ばない = キーのレート制限を節約)
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  const cacheKey = new Request(`${new URL(req.url).origin}/asset/${id}`);
  if (cache) {
    try {
      const hit = await cache.match(cacheKey);
      if (hit) {
        const h = new Headers(hit.headers);
        for (const [k, v] of Object.entries(cors)) h.set(k, v);
        return new Response(hit.body, { status: 200, headers: h });
      }
    } catch (e) { /* キャッシュ不可の環境では無視 */ }
  }

  let meta;
  try {
    const r = await fetch(ASSET_API + id, { headers: { 'x-api-key': env.ROBLOX_API_KEY, Accept: 'application/json' } });
    if (r.status === 401 || r.status === 403) return json({ error: 'KEY_REJECTED', status: r.status }, 401, cors);
    if (r.status === 404) return json({ error: 'NOT_FOUND' }, 404, cors);
    if (r.status === 429) return json({ error: 'RATE_LIMITED' }, 429, cors);
    if (!r.ok) return json({ error: 'UPSTREAM', status: r.status }, 502, cors);
    meta = await r.json();
  } catch (e) {
    return json({ error: 'UPSTREAM' }, 502, cors);
  }

  let loc;
  try { loc = new URL(meta && meta.location); } catch (e) { return json({ error: 'NO_LOCATION' }, 502, cors); }
  if (!allowedHost(loc)) return json({ error: 'BAD_LOCATION' }, 502, cors);

  let cdn;
  try { cdn = await fetch(loc.toString(), { cf: { cacheEverything: true, cacheTtl: 86400 } }); }
  catch (e) { return json({ error: 'CDN' }, 502, cors); }
  if (!cdn.ok) return json({ error: 'CDN', status: cdn.status }, 502, cors);

  const headers = new Headers(cors);
  headers.set('Content-Type', cdn.headers.get('Content-Type') || 'application/octet-stream');
  headers.set('Cache-Control', 'public, max-age=86400');
  const resp = new Response(cdn.body, { status: 200, headers });
  if (cache && ctx && ctx.waitUntil) {
    ctx.waitUntil(Promise.resolve().then(() => cache.put(cacheKey, resp.clone())).catch(() => {}));
  }
  return resp;
}

async function handleProxy(req, cors) {
  const raw = new URL(req.url).searchParams.get('url');
  let target;
  try { target = new URL(raw); } catch (e) { return new Response('bad url', { status: 400, headers: cors }); }
  if (!allowedHost(target)) return new Response('host not allowed', { status: 403, headers: cors });

  // 注意: この経路ではAPIキーを付けない(キー付きの中継にしないため)
  const init = { method: req.method, headers: { Accept: req.headers.get('Accept') || '*/*' }, redirect: 'follow' };
  if (req.method === 'POST') {
    init.headers['Content-Type'] = req.headers.get('Content-Type') || 'application/json';
    init.body = await req.arrayBuffer();
  }
  if (/rbxcdn/.test(target.hostname)) init.cf = { cacheEverything: true, cacheTtl: 86400 };

  let upstream;
  try { upstream = await fetch(target.toString(), init); }
  catch (e) { return new Response('upstream error', { status: 502, headers: cors }); }

  const h = new Headers(upstream.headers);
  h.delete('set-cookie');
  for (const [k, v] of Object.entries(cors)) h.set(k, v);
  return new Response(upstream.body, { status: upstream.status, headers: h });
}

export default {
  async fetch(req, env, ctx) {
    const cors = corsHeaders(env, req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'GET' && req.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: cors });
    }
    const url = new URL(req.url);

    if (url.pathname === '/health') {
      return json({ ok: true, hasApiKey: Boolean(env && env.ROBLOX_API_KEY), version: 2 }, 200, cors);
    }
    if (!originOk(env, req)) return json({ error: 'ORIGIN_NOT_ALLOWED' }, 403, cors);

    const m = ASSET_PATH.exec(url.pathname);
    if (m && req.method === 'GET') return handleAsset(m[1], env, req, ctx, cors);

    return handleProxy(req, cors);
  },
};
