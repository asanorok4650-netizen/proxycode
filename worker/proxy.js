// Cloudflare Worker: Roblox用プロキシ(v3)
//
//   GET  /health            → { ok, hasApiKey, originRestricted, rateLimit, version }   接続確認(キーの値は返さない)
//   GET  /asset/{id}        → アセット本体(Open Cloud Asset Delivery をAPIキーで呼び、CDNから取得して返す)
//   GET|POST /?url=<URL>    → users / avatar の公開API用の中継(APIキーは付けない)。転送できるのは PROXY_RULES に書いたものだけ
//
// 設定:
//   ROBLOX_API_KEY  (シークレット)  Open CloudのAPIキー。コードやwrangler.tomlには書かない。
//                                  npx wrangler secret put ROBLOX_API_KEY  /  ダッシュボードの「変数とシークレット」
//   ALLOWED_ORIGIN  (変数)          例: https://your-site.pages.dev(カンマ区切りで複数可)。設定すると、そのOriginのリクエストだけ受け付ける。
//                                  秘密の値ではないので wrangler.toml の [vars] に書いてよい。未設定だと誰でも使える(/health に出る)。
//   RL_REQUEST / RL_UPSTREAM  (Rate Limiting バインディング・任意)  wrangler.toml 参照。無ければ制限なしで動く。
//
// 背景: 2025-04-02以降、Asset Deliveryは認証なしだと401を返すため、アセット取得にはAPIキーが必要。

// 汎用の中継(?url=)で転送してよいリクエスト。アプリが使うものだけを許可する。増やすときはここに足す。
const PROXY_RULES = [
  { host: 'users.roblox.com', method: 'POST', path: /^\/v1\/usernames\/users$/ },
  { host: 'users.roblox.com', method: 'GET', path: /^\/v1\/users\/\d{1,19}$/ },
  { host: 'avatar.roblox.com', method: 'GET', path: /^\/v1\/users\/\d{1,19}\/avatar$/ },
];

// アセットの実体(Asset Deliveryが教えてくるCDNのURL)として受け付けるホスト
const CDN_HOSTS = [/(^|\.)roblox\.com$/, /(^|\.)rbxcdn\.com$/];
const ASSET_API = 'https://apis.roblox.com/asset-delivery-api/v1/assetId/';
const ASSET_PATH = /^\/asset\/(\d{1,19})$/;

const MAX_BODY_BYTES = 16 * 1024;          // 中継するPOSTの本文の上限
const MAX_ASSET_BYTES = 64 * 1024 * 1024;  // 返すアセットの上限
const RETRY_AFTER_SECONDS = 30;

const originList = (env) => String((env && env.ALLOWED_ORIGIN) || '*').split(',').map((s) => s.trim()).filter(Boolean);
const restricted = (env) => { const l = originList(env); return l.length > 0 && !l.includes('*'); };

// ALLOWED_ORIGIN が設定されている場合、一致したOriginだけを返す(Access-Control-Allow-Origin は1つだけ返せるため)
function corsHeaders(env, req) {
  const list = originList(env);
  const origin = req.headers.get('Origin');
  const allow = !restricted(env) ? '*' : (origin && list.includes(origin) ? origin : list[0]);
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': req.headers.get('Access-Control-Request-Headers') || 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
  };
}

const json = (obj, status, cors, extra) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors, ...(extra || {}), 'Content-Type': 'application/json' } });
const tooMany = (cors) => json({ error: 'RATE_LIMITED' }, 429, cors, { 'Retry-After': String(RETRY_AFTER_SECONDS) });

// ※Originはブラウザ以外なら偽装できるため、これは「他のサイトからのうっかり利用」を防ぐ程度の保護。悪用の歯止めはレート制限と転送先の限定。
function originOk(env, req) {
  if (!restricted(env)) return true;
  return originList(env).includes(req.headers.get('Origin'));
}

// Rate Limitingバインディングは「Cloudflareの拠点ごと」の近似値。無い環境では何もしない
async function limited(binding, key) {
  if (!binding || typeof binding.limit !== 'function') return false;
  try { const { success } = await binding.limit({ key }); return !success; } catch (e) { return false; }
}
const clientKey = (req) => req.headers.get('CF-Connecting-IP') || 'unknown';

const cdnHost = (u) => u.protocol === 'https:' && CDN_HOSTS.some((re) => re.test(u.hostname));

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

  // ここから先はRobloxを呼ぶ(キーを消費する)ので、IPごとに厳しめに制限する
  if (await limited(env.RL_UPSTREAM, clientKey(req))) return tooMany(cors);

  let meta;
  try {
    const r = await fetch(ASSET_API + id, { headers: { 'x-api-key': env.ROBLOX_API_KEY, Accept: 'application/json' } });
    if (r.status === 401 || r.status === 403) return json({ error: 'KEY_REJECTED', status: r.status }, 401, cors);
    if (r.status === 404) return json({ error: 'NOT_FOUND' }, 404, cors);
    if (r.status === 429) return json({ error: 'RATE_LIMITED' }, 429, cors, { 'Retry-After': String(RETRY_AFTER_SECONDS) });
    if (!r.ok) return json({ error: 'UPSTREAM', status: r.status }, 502, cors);
    meta = await r.json();
  } catch (e) {
    return json({ error: 'UPSTREAM' }, 502, cors);
  }

  let loc;
  try { loc = new URL(meta && meta.location); } catch (e) { return json({ error: 'NO_LOCATION' }, 502, cors); }
  if (!cdnHost(loc)) return json({ error: 'BAD_LOCATION' }, 502, cors);

  let cdn;
  try { cdn = await fetch(loc.toString(), { redirect: 'manual', cf: { cacheEverything: true, cacheTtl: 86400 } }); }
  catch (e) { return json({ error: 'CDN' }, 502, cors); }
  if (!cdn.ok) return json({ error: 'CDN', status: cdn.status }, 502, cors);
  if (Number(cdn.headers.get('Content-Length')) > MAX_ASSET_BYTES) return json({ error: 'TOO_LARGE' }, 413, cors);

  const headers = new Headers(cors);
  headers.set('Content-Type', cdn.headers.get('Content-Type') || 'application/octet-stream');
  headers.set('Cache-Control', 'public, max-age=86400');
  const resp = new Response(cdn.body, { status: 200, headers });
  if (cache && ctx && ctx.waitUntil) {
    ctx.waitUntil(Promise.resolve().then(() => cache.put(cacheKey, resp.clone())).catch(() => {}));
  }
  return resp;
}

async function handleProxy(req, env, cors) {
  const raw = new URL(req.url).searchParams.get('url');
  let target;
  try { target = new URL(raw); } catch (e) { return new Response('bad url', { status: 400, headers: cors }); }
  // 転送してよいのは、PROXY_RULES に載っている https のホスト・メソッド・パスだけ(ユーザー名・パスワード付きURLや別ポートも不可)
  const ok = target.protocol === 'https:' && !target.username && !target.password && !target.port
    && PROXY_RULES.some((r) => r.host === target.hostname && r.method === req.method && r.path.test(target.pathname));
  if (!ok) return new Response('not allowed', { status: 403, headers: cors });

  let body;
  if (req.method === 'POST') {
    if (Number(req.headers.get('Content-Length')) > MAX_BODY_BYTES) return new Response('too large', { status: 413, headers: cors });
    body = await req.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) return new Response('too large', { status: 413, headers: cors });
  }

  if (await limited(env && env.RL_UPSTREAM, clientKey(req))) return tooMany(cors);

  // 注意: この経路ではAPIキーを付けない(キー付きの中継にしないため)。リダイレクトは追わない(許可していないホストへ飛ばされないように)
  const init = { method: req.method, headers: { Accept: req.headers.get('Accept') || '*/*' }, redirect: 'manual' };
  if (body) { init.headers['Content-Type'] = req.headers.get('Content-Type') || 'application/json'; init.body = body; }

  let upstream;
  try { upstream = await fetch(target.toString(), init); }
  catch (e) { return new Response('upstream error', { status: 502, headers: cors }); }
  if (upstream.status >= 300 && upstream.status < 400) return new Response('redirect not allowed', { status: 502, headers: cors });

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
      return json({
        ok: true, hasApiKey: Boolean(env && env.ROBLOX_API_KEY), originRestricted: restricted(env),
        rateLimit: Boolean(env && env.RL_REQUEST && env.RL_UPSTREAM), version: 3,
      }, 200, cors);
    }
    if (!originOk(env, req)) return json({ error: 'ORIGIN_NOT_ALLOWED' }, 403, cors);
    if (await limited(env && env.RL_REQUEST, clientKey(req))) return tooMany(cors); // 全リクエスト(キャッシュに当たるものも)の上限

    const m = ASSET_PATH.exec(url.pathname);
    if (m && req.method === 'GET') return handleAsset(m[1], env, req, ctx, cors);

    return handleProxy(req, env, cors);
  },
};
