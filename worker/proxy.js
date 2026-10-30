// Cloudflare Worker: Roblox API用のCORSプロキシ
// 使い方: GET/POST https://<worker>/?url=<エンコードしたRobloxのURL>
// デプロイ: wrangler deploy (wrangler.toml の main = "worker/proxy.js")
// 環境変数 ALLOWED_ORIGIN を設定すると、そのオリジンからのみ許可(未設定は *)。

const ALLOWED_HOSTS = [/(^|\.)roblox\.com$/, /(^|\.)rbxcdn\.com$/];

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

export default {
  async fetch(req, env) {
    const cors = corsHeaders(env, req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'GET' && req.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: cors });
    }

    const raw = new URL(req.url).searchParams.get('url');
    let target;
    try { target = new URL(raw); } catch (e) { return new Response('bad url', { status: 400, headers: cors }); }
    if (target.protocol !== 'https:' || !ALLOWED_HOSTS.some((re) => re.test(target.hostname))) {
      return new Response('host not allowed', { status: 403, headers: cors });
    }

    const init = { method: req.method, headers: { Accept: req.headers.get('Accept') || '*/*' }, redirect: 'follow' };
    if (req.method === 'POST') {
      init.headers['Content-Type'] = req.headers.get('Content-Type') || 'application/json';
      init.body = await req.arrayBuffer();
    }
    const isAsset = /assetdelivery|rbxcdn/.test(target.hostname);
    if (isAsset) init.cf = { cacheEverything: true, cacheTtl: 86400 };

    let upstream;
    try { upstream = await fetch(target.toString(), init); }
    catch (e) { return new Response('upstream error', { status: 502, headers: cors }); }

    const h = new Headers(upstream.headers);
    h.delete('set-cookie');
    for (const [k, v] of Object.entries(cors)) h.set(k, v);
    return new Response(upstream.body, { status: upstream.status, headers: h });
  },
};
