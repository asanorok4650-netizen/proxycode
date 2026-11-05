// プロキシ(worker/proxy.js)のテスト。fetch と Rate Limiting バインディングを代役にして Node で動かす。
//   node test/proxy.test.mjs
import assert from 'node:assert/strict';
import worker from '../worker/proxy.js';

const SITE = 'https://site.example';
const env = (o = {}) => ({ ALLOWED_ORIGIN: SITE, ROBLOX_API_KEY: 'KEY', ...o });
const rl = (ok = true) => ({ calls: [], async limit(a) { this.calls.push(a.key); return { success: ok }; } });

let upstream = []; // fetch の呼び出し記録
let reply = () => new Response('{"ok":1}', { status: 200, headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'a=b' } });
globalThis.fetch = async (url, init) => { upstream.push({ url: String(url), init: init || {} }); return reply(url, init); };

const call = (path, o = {}, e = env()) => worker.fetch(new Request('https://proxy.test' + path, {
  method: o.method || 'GET', headers: { Origin: SITE, 'CF-Connecting-IP': '1.2.3.4', ...(o.headers || {}) }, body: o.body
}), e, { waitUntil() {} });
const px = (u, o) => call('/?url=' + encodeURIComponent(u), o);
const reset = () => { upstream = []; };

// /health: Origin不要。キーの値は返さない
{
  const r = await call('/health', { headers: { Origin: 'https://other.example' } });
  const b = await r.json();
  assert.equal(r.status, 200); assert.equal(b.hasApiKey, true); assert.equal(b.originRestricted, true); assert.equal(b.rateLimit, false);
  assert.ok(!JSON.stringify(b).includes('KEY'));
  assert.equal((await (await call('/health', {}, { })).json()).originRestricted, false, 'ALLOWED_ORIGIN未設定だと制限なしと分かる');
}

// Origin: 一致するものだけ。複数指定ではリクエストのOriginを返す。Origin無しも拒否
{
  reset();
  assert.equal((await px('https://users.roblox.com/v1/users/1', { headers: { Origin: 'https://evil.example' } })).status, 403);
  const noOrigin = new Request('https://proxy.test/?url=' + encodeURIComponent('https://users.roblox.com/v1/users/1'));
  assert.equal((await worker.fetch(noOrigin, env(), {})).status, 403);
  assert.equal(upstream.length, 0, '拒否したらRobloxを呼ばない');
  const multi = env({ ALLOWED_ORIGIN: 'https://a.example, https://b.example' });
  const r = await call('/?url=' + encodeURIComponent('https://users.roblox.com/v1/users/1'), { headers: { Origin: 'https://b.example' } }, multi);
  assert.equal(r.status, 200); assert.equal(r.headers.get('Access-Control-Allow-Origin'), 'https://b.example');
  assert.equal(r.headers.get('Vary'), 'Origin');
  const pre = await worker.fetch(new Request('https://proxy.test/', { method: 'OPTIONS', headers: { Origin: SITE } }), env(), {});
  assert.equal(pre.status, 204); assert.equal(pre.headers.get('Access-Control-Allow-Origin'), SITE);
}

// 転送先の限定: 許可した ホスト・メソッド・パス だけ通る
{
  reset();
  const ok = await px('https://users.roblox.com/v1/users/123');
  assert.equal(ok.status, 200); assert.equal(ok.headers.get('Set-Cookie'), null, 'Set-Cookie は返さない');
  assert.equal((await px('https://avatar.roblox.com/v1/users/123/avatar')).status, 200);
  assert.equal((await px('https://users.roblox.com/v1/usernames/users', { method: 'POST', body: '{"usernames":["a"]}' })).status, 200);
  const n = upstream.length; assert.equal(n, 3);
  for (const u of [
    'https://evil.example/v1/users/1', 'https://www.roblox.com/v1/users/1', 'https://apis.roblox.com/asset-delivery-api/v1/assetId/1',
    'https://auth.roblox.com/v2/logout', 'https://users.roblox.com/v1/users/abc', 'https://users.roblox.com/v1/users/1/extra',
    'https://users.roblox.com/v1/users/1/../../x', 'https://users.roblox.com.evil.example/v1/users/1', 'http://users.roblox.com/v1/users/1',
    'https://users.roblox.com:8443/v1/users/1', 'https://user:pw@users.roblox.com/v1/users/1', 'https://thumbnails.rbxcdn.com/x'
  ]) assert.equal((await px(u)).status, 403, u);
  assert.equal((await px('https://users.roblox.com/v1/usernames/users')).status, 403, 'GETでは usernames を呼べない');
  assert.equal((await px('https://users.roblox.com/v1/users/1', { method: 'POST', body: '{}' })).status, 403, 'POSTでは users/{id} を呼べない');
  assert.equal((await px('not a url')).status, 400);
  assert.equal(upstream.length, n, '拒否したものはRobloxを呼ばない');
  assert.equal((await call('/', { method: 'PUT' })).status, 405);
}

// この経路ではAPIキーを付けない。リダイレクトは追わない
{
  reset();
  await px('https://users.roblox.com/v1/users/1');
  assert.ok(!JSON.stringify(upstream[0].init.headers).toLowerCase().includes('x-api-key'));
  assert.equal(upstream[0].init.redirect, 'manual');
  const saved = reply;
  reply = () => new Response(null, { status: 302, headers: { Location: 'https://evil.example/' } });
  assert.equal((await px('https://users.roblox.com/v1/users/1')).status, 502);
  reply = saved;
}

// POSTの本文の上限
{
  reset();
  const big = 'x'.repeat(17 * 1024);
  const r = await px('https://users.roblox.com/v1/usernames/users', { method: 'POST', body: big });
  assert.equal(r.status, 413); assert.equal(upstream.length, 0);
}

// レート制限: 全リクエスト(RL_REQUEST)とRobloxを呼ぶ分(RL_UPSTREAM)。バインディングが無くても動く
{
  reset();
  const all = rl(false), up = rl(true);
  const r = await call('/?url=' + encodeURIComponent('https://users.roblox.com/v1/users/1'), {}, env({ RL_REQUEST: all, RL_UPSTREAM: up }));
  assert.equal(r.status, 429); assert.equal((await r.json()).error, 'RATE_LIMITED'); assert.ok(Number(r.headers.get('Retry-After')) > 0);
  assert.equal(upstream.length, 0); assert.deepEqual(all.calls, ['1.2.3.4']); assert.equal(up.calls.length, 0);
  const ok = rl(true), upLimited = rl(false);
  const r2 = await call('/?url=' + encodeURIComponent('https://users.roblox.com/v1/users/1'), {}, env({ RL_REQUEST: ok, RL_UPSTREAM: upLimited }));
  assert.equal(r2.status, 429); assert.equal(upstream.length, 0, '制限に掛かったらRobloxを呼ばない');
  const r3 = await call('/asset/5', {}, env({ RL_REQUEST: ok, RL_UPSTREAM: upLimited }));
  assert.equal(r3.status, 429); assert.equal(upstream.length, 0);
  assert.equal((await call('/health', {}, env({ RL_REQUEST: rl(false), RL_UPSTREAM: rl(false) }))).status, 200, '/health は制限しない');
  assert.equal((await (await call('/health', {}, env({ RL_REQUEST: ok, RL_UPSTREAM: ok }))).json()).rateLimit, true);
  const broken = { limit: async () => { throw new Error('x'); } };
  assert.equal((await call('/?url=' + encodeURIComponent('https://users.roblox.com/v1/users/1'), {}, env({ RL_REQUEST: broken, RL_UPSTREAM: broken }))).status, 200, '制限の仕組みが壊れても止めない');
}

// アセット: キーはAsset Deliveryにだけ付く。実体のホストを限定。上限サイズ。キー無しは503
{
  reset();
  assert.equal((await call('/asset/5', {}, env({ ROBLOX_API_KEY: '' }))).status, 503);
  assert.equal((await call('/asset/abc')).status, 400, '数字でないidは汎用経路に落ち、urlが無いので400');
  const mk = (loc, cdnInit) => (url) => String(url).startsWith('https://apis.roblox.com/')
    ? new Response(JSON.stringify({ location: loc }), { status: 200 })
    : new Response('BIN', { status: 200, headers: { 'Content-Type': 'image/png', ...(cdnInit || {}) } });
  const saved = reply;
  reply = mk('https://c0.rbxcdn.com/abc');
  const r = await call('/asset/5');
  assert.equal(r.status, 200); assert.equal(await r.text(), 'BIN'); assert.equal(r.headers.get('Content-Type'), 'image/png');
  assert.equal(upstream[0].init.headers['x-api-key'], 'KEY'); assert.ok(!('x-api-key' in (upstream[1].init.headers || {})), 'CDNにはキーを送らない');
  reset(); reply = mk('https://evil.example/abc');
  assert.equal((await call('/asset/5')).status, 502); assert.equal(upstream.length, 1, '許可外のホストへは取りに行かない');
  reset(); reply = mk('http://c0.rbxcdn.com/abc');
  assert.equal((await call('/asset/5')).status, 502);
  reply = mk('https://c0.rbxcdn.com/abc', { 'Content-Length': String(65 * 1024 * 1024) });
  assert.equal((await call('/asset/5')).status, 413);
  reply = saved;
}
console.log('proxy: ok');
