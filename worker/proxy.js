// Cloudflare Worker: Roblox用プロキシ(v4)
//
//   GET  /                  → 詰まり解消ページ(パスコードでレート制限を一時的に解除/再開・アセット取得テスト)
//   POST /unlock, /lock     → 上のページが呼ぶ。body: { passcode }。解除は BYPASS_SECONDS 秒で自動的に元に戻る
//   POST /test              → 上のページが呼ぶ。body: { passcode, assetId }。Robloxの応答(ステータス・ヘッダー・本文)をそのまま返す
//   GET  /health            → { ok, hasApiKey, originRestricted, rateLimit, rateLimitBypass, version }   接続確認(キーの値は返さない)
//   GET  /asset/{id}        → アセット本体(Open Cloud Asset Delivery をAPIキーで呼び、CDNから取得して返す)
//   GET|POST /?url=<URL>    → users / avatar の公開API用の中継(APIキーは付けない)。転送できるのは PROXY_RULES に書いたものだけ
//
// 設定:
//   ROBLOX_API_KEY  (シークレット)  Open CloudのAPIキー(権限は legacy-asset:manage)。コードやwrangler.tomlには書かない。
//                                  ダッシュボードの「変数とシークレット」で種類を「シークレット」にして設定
//   ADMIN_PASSCODE  (シークレット)  詰まり解消ページのパスコード。長く推測されにくいものにする(16文字以上推奨)。
//   RL_BYPASS       (KVバインディング)  解除フラグの保存先。無いと解除機能は使えない(他は動く)。
//   ALLOWED_ORIGIN  (変数)          例: https://your-site.pages.dev(カンマ区切りで複数可)。設定すると、そのOriginのリクエストだけ受け付ける。
//                                  秘密の値ではないので wrangler.toml の [vars] に書いてよい。未設定だと誰でも使える(/health に出る)。
//   RL_REQUEST / RL_UPSTREAM  (Rate Limiting バインディング・任意)  wrangler.toml 参照。無ければ制限なしで動く。
//
// 背景: 2025-04-02以降、Asset Deliveryは認証なしだと401を返すため、アセット取得にはAPIキーが必要。
//
// 429の出どころは { error: 'RATE_LIMITED', source, retryAfter } の source で見分ける:
//   worker-request  … RL_REQUEST(全リクエストの上限)   → パスコードで解除できる
//   worker-upstream … RL_UPSTREAM(Robloxを呼ぶ分の上限) → パスコードで解除できる
//   roblox          … Roblox側(APIキー)の上限。retryAfter はRobloxの Retry-After(秒)をそのまま使う → 解除できない

// 汎用の中継(?url=)で転送してよいリクエスト。アプリが使うものだけを許可する。増やすときはここに足す。
const PROXY_RULES = [
  { host: 'users.roblox.com', method: 'POST', path: /^\/v1\/usernames\/users$/ },
  { host: 'users.roblox.com', method: 'GET', path: /^\/v1\/users\/\d{1,19}$/ },
  { host: 'avatar.roblox.com', method: 'GET', path: /^\/v1\/users\/\d{1,19}\/avatar$/ },
];

// アセットの実体(Asset Deliveryが教えてくれるCDNのURL)として受け付けるホスト
const CDN_HOSTS = [/(^|\.)roblox\.com$/, /(^|\.)rbxcdn\.com$/];
const ASSET_API = 'https://apis.roblox.com/asset-delivery-api/v1/assetId/';
const ASSET_PATH = /^\/asset\/(\d{1,19})$/;

const MAX_BODY_BYTES = 16 * 1024;          // 中継するPOSTの本文の上限
const MAX_ASSET_BYTES = 64 * 1024 * 1024;  // 返すアセットの上限
const RETRY_AFTER_SECONDS = 30;
const BYPASS_SECONDS = 3600;               // 解除の有効時間(KVの最小は60秒)。過ぎると自動で元に戻る
const TEST_BODY_CHARS = 4000;              // アセット取得テストで返す本文の最大文字数

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
const tooMany = (cors, source, retryAfter) => {
  const sec = retryAfter || RETRY_AFTER_SECONDS;
  return json({ error: 'RATE_LIMITED', source, retryAfter: sec }, 429, cors, { 'Retry-After': String(sec) });
};

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

// 詰まり解消: 解除フラグ(KV)が立っている間はレート制限を無視する。
// 制限に当たったときだけ読むので、普段はKVを読まない。KVの反映は最大1分ほど遅れることがある。
async function bypassed(env) {
  if (!env || !env.RL_BYPASS) return false;
  try { return (await env.RL_BYPASS.get('bypass', { cacheTtl: 30 })) === '1'; } catch (e) { return false; }
}
async function overLimit(env, name, req) {
  if (!(await limited(env && env[name], clientKey(req)))) return false;
  return !(await bypassed(env));
}

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
  if (await overLimit(env, 'RL_UPSTREAM', req)) return tooMany(cors, 'worker-upstream');

  let meta;
  try {
    const r = await fetch(ASSET_API + id, { headers: { 'x-api-key': env.ROBLOX_API_KEY, Accept: 'application/json' } });
    if (r.status === 401 || r.status === 403) return json({ error: 'KEY_REJECTED', status: r.status }, 401, cors);
    if (r.status === 404) return json({ error: 'NOT_FOUND' }, 404, cors);
    if (r.status === 429) {
      // Robloxが返した Retry-After(秒)をそのまま伝える。無い・不正なら既定値(上限1時間)
      const ra = Number(r.headers.get('Retry-After'));
      return tooMany(cors, 'roblox', Number.isFinite(ra) && ra > 0 ? Math.min(Math.ceil(ra), 3600) : undefined);
    }
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

  if (await overLimit(env, 'RL_UPSTREAM', req)) return tooMany(cors, 'worker-upstream');

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

// ---- 詰まり解消ページ ----
// CORSヘッダは付けない(他サイトのページからは結果を読めない)。Originの制限・レート制限の手前で処理するので、詰まっていても開ける。

const ADMIN_HTML = `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>プロキシ 詰まり解消</title>
<style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.6}
input,button{font-size:1rem;padding:.6rem;width:100%;box-sizing:border-box;margin:.3rem 0}
button{cursor:pointer}
#st,#msg{padding:.6rem;border-radius:.4rem;background:#8882}
pre{padding:.6rem;border-radius:.4rem;background:#8882;white-space:pre-wrap;word-break:break-all;font-size:.8rem}
</style></head><body>
<h1>詰まり解消</h1>
<p id="st">状態を確認中…</p>
<input id="pw" type="password" placeholder="パスコード" autocomplete="current-password">
<button id="on">レート制限を解除する(1時間)</button>
<button id="off">レート制限を再開する</button>
<p id="msg" hidden></p>
<h2>アセット取得テスト</h2>
<input id="aid" type="text" inputmode="numeric" placeholder="アセットID(数字)">
<button id="test">Robloxに1件リクエストして結果を見る</button>
<pre id="out" hidden></pre>
<p><small>解除中はこのWorkerのレート制限(RL_REQUEST / RL_UPSTREAM)だけが無効になります。Roblox側の429は解除できません。反映まで最大1分ほどかかることがあります。テストはRobloxを1回呼び、APIキーの枠を消費します(Workerのレート制限は通りません)。</small></p>
<script>
const $=(i)=>document.getElementById(i);
async function refresh(){
  try{
    const h=await (await fetch('/health')).json();
    $('st').textContent='レート制限: '+(h.rateLimit?'設定あり':'設定なし')+' / 解除: '+(h.rateLimitBypass?'中(解除されている)':'していない');
  }catch(e){$('st').textContent='状態を取得できませんでした';}
}
async function act(path){
  const m=$('msg');m.hidden=false;m.textContent='送信中…';
  try{
    const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode:$('pw').value})});
    const j=await r.json();
    m.textContent=r.ok?(j.bypass?'解除しました(約'+Math.round(j.seconds/60)+'分間)':'再開しました'):'失敗: '+j.error;
  }catch(e){m.textContent='通信に失敗しました';}
  refresh();
}
async function runTest(){
  const o=$('out');o.hidden=false;o.textContent='送信中…';
  try{
    const r=await fetch('/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode:$('pw').value,assetId:$('aid').value})});
    o.textContent=JSON.stringify(await r.json(),null,2);
  }catch(e){o.textContent='通信に失敗しました';}
}
$('on').onclick=()=>act('/unlock');
$('off').onclick=()=>act('/lock');
$('test').onclick=runTest;
refresh();
</script></body></html>`;

const adminJson = (obj, status) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

// パスコードの比較(長さや一致位置が時間でばれないよう、ハッシュにして全バイト比べる)
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// アセット取得テスト: Roblox(Asset Delivery)の応答のステータス・ヘッダー・本文をそのまま返す。
// 429の原因(Roblox側か自分側か)や Retry-After、x-ratelimit系のヘッダーを確認するためのもの。
async function runTest(env, rawId) {
  const id = String(rawId || '').trim();
  if (!/^\d{1,19}$/.test(id)) return adminJson({ error: 'BAD_ASSET_ID' }, 400);
  if (!env.ROBLOX_API_KEY) return adminJson({ error: 'NO_API_KEY' }, 503);
  const t0 = Date.now();
  try {
    const r = await fetch(ASSET_API + id, { headers: { 'x-api-key': env.ROBLOX_API_KEY, Accept: 'application/json' } });
    const text = await r.text();
    const headers = {};
    r.headers.forEach((v, k) => { if (k !== 'set-cookie') headers[k] = v; });
    return adminJson({
      ok: r.ok, status: r.status, statusText: r.statusText, ms: Date.now() - t0,
      headers, body: text.slice(0, TEST_BODY_CHARS), truncated: text.length > TEST_BODY_CHARS,
    }, 200);
  } catch (e) {
    return adminJson({ error: 'FETCH_FAILED', message: String((e && e.message) || e) }, 502);
  }
}

async function handleAdmin(req, env, path) {
  if (path === '/') {
    return new Response(ADMIN_HTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'",
      },
    });
  }
  if (req.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  if (!env || !env.ADMIN_PASSCODE) return adminJson({ error: 'NO_PASSCODE_CONFIGURED' }, 503);
  if (path !== '/test' && !env.RL_BYPASS) return adminJson({ error: 'NO_KV_BINDING' }, 503);
  if (Number(req.headers.get('Content-Length')) > 1024) return adminJson({ error: 'TOO_LARGE' }, 413);

  let b;
  try { b = await req.json(); } catch (e) { b = {}; }
  const good = b && typeof b.passcode === 'string' && await safeEqual(b.passcode, String(env.ADMIN_PASSCODE));
  if (!good) {
    await new Promise((r) => setTimeout(r, 1000)); // 総当たりを遅くする(パスコードは長くすること)
    return adminJson({ error: 'BAD_PASSCODE' }, 401);
  }
  if (path === '/test') return runTest(env, b.assetId);
  try {
    if (path === '/unlock') {
      await env.RL_BYPASS.put('bypass', '1', { expirationTtl: BYPASS_SECONDS });
      return adminJson({ ok: true, bypass: true, seconds: BYPASS_SECONDS }, 200);
    }
    await env.RL_BYPASS.delete('bypass');
    return adminJson({ ok: true, bypass: false }, 200);
  } catch (e) {
    return adminJson({ error: 'KV_ERROR' }, 500);
  }
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
        rateLimit: Boolean(env && env.RL_REQUEST && env.RL_UPSTREAM), rateLimitBypass: await bypassed(env), version: 4,
      }, 200, cors);
    }
    // 詰まり解消ページ(Origin制限・レート制限より前に処理する)。/ に ?url= が付いていれば従来どおり中継
    if ((url.pathname === '/' && !url.searchParams.has('url') && req.method === 'GET')
      || url.pathname === '/unlock' || url.pathname === '/lock' || url.pathname === '/test') {
      return handleAdmin(req, env, url.pathname);
    }
    if (!originOk(env, req)) return json({ error: 'ORIGIN_NOT_ALLOWED' }, 403, cors);
    if (await overLimit(env, 'RL_REQUEST', req)) return tooMany(cors, 'worker-request'); // 全リクエスト(キャッシュに当たるものも)の上限

    const m = ASSET_PATH.exec(url.pathname);
    if (m && req.method === 'GET') return handleAsset(m[1], env, req, ctx, cors);

    return handleProxy(req, env, cors);
  },
};
