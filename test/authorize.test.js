import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  REDIRECT_URI, addClient, authorizeUrl, createTestIdp, pkce, pollStatus, startLogin, tgUser,
} from './helpers.js';

const challenge = pkce().challenge;

function redirectParams(res) {
  assert.equal(res.statusCode, 302, res.body);
  const url = new URL(res.headers.location);
  assert.equal(`${url.origin}${url.pathname}`, REDIRECT_URI);
  return url.searchParams;
}

test('redirect_uri must match a registered URI exactly', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const variants = [
    'https://client.example.com/callback/',
    'https://client.example.com/callback?x=1',
    'https://client.example.com/Callback',
    'https://CLIENT.example.com/callback',
    'http://client.example.com/callback',
    'https://client.example.com:443/callback',
    'https://client.example.com/callback#frag',
    'https://client.example.com.evil.test/callback',
    'https://client.example.com/callback/../callback',
  ];
  for (const redirect_uri of variants) {
    const res = await idp.app.inject({ url: authorizeUrl({ redirect_uri, code_challenge: challenge }) });
    assert.equal(res.statusCode, 400, redirect_uri);
    assert.equal(res.headers.location, undefined, `must not redirect to ${redirect_uri}`);
    assert.match(res.body, /redirect_uri is not registered/);
  }
  const ok = await idp.app.inject({ url: authorizeUrl({ code_challenge: challenge }) });
  assert.equal(ok.statusCode, 200);
});

test('unknown client renders an error page instead of redirecting', async () => {
  const idp = await createTestIdp();
  const res = await idp.app.inject({ url: authorizeUrl({ client_id: 'nope', code_challenge: challenge }) });
  assert.equal(res.statusCode, 400);
  assert.equal(res.headers.location, undefined);
  assert.match(res.headers['content-type'], /text\/html/);
});

test('protocol errors are redirected to the client with error and state', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);

  let p = redirectParams(await idp.app.inject({ url: authorizeUrl({ response_type: 'token', state: 'st', code_challenge: challenge }) }));
  assert.equal(p.get('error'), 'unsupported_response_type');
  assert.equal(p.get('state'), 'st');
  assert.equal(p.get('iss'), 'https://idp.test');

  p = redirectParams(await idp.app.inject({ url: authorizeUrl({ state: 'st' }) }));
  assert.equal(p.get('error'), 'invalid_request');
  assert.match(p.get('error_description'), /code_challenge/);

  p = redirectParams(await idp.app.inject({ url: authorizeUrl({ code_challenge: challenge, code_challenge_method: 'plain' }) }));
  assert.equal(p.get('error'), 'invalid_request');

  p = redirectParams(await idp.app.inject({ url: authorizeUrl({ code_challenge: 'too-short' }) }));
  assert.equal(p.get('error'), 'invalid_request');

  p = redirectParams(await idp.app.inject({ url: authorizeUrl({ code_challenge: challenge, prompt: 'none' }) }));
  assert.equal(p.get('error'), 'login_required');
});

test('repeated parameters are rejected', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const res = await idp.app.inject({ url: `${authorizeUrl({ code_challenge: challenge })}&scope=openid&scope=telegram` });
  assert.equal(redirectParams(res).get('error'), 'invalid_request');
});

test('scope enforcement: scopes outside allowed_scopes are refused', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { scopes: 'openid profile' });
  const p = redirectParams(await idp.app.inject({ url: authorizeUrl({ code_challenge: challenge, scope: 'openid telegram', state: 's' }) }));
  assert.equal(p.get('error'), 'invalid_scope');
  assert.equal(p.get('state'), 's');

  const unknown = redirectParams(await idp.app.inject({ url: authorizeUrl({ code_challenge: challenge, scope: 'openid admin' }) }));
  assert.equal(unknown.get('error'), 'invalid_scope');

  // No scope requested → default scopes intersected with what the client may have.
  const { token } = await startLogin(idp.app, { code_challenge: challenge });
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, tgUser());
  assert.deepEqual(outcome.scopes, ['openid', 'profile']);
});

test('consent is recorded only for the scopes actually granted', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { token } = await startLogin(idp.app, { code_challenge: challenge, scope: 'openid' });
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, tgUser());
  idp.ctx.oauth.approveLogin(outcome.authRequestId, tgUser());
  const user = idp.ctx.store.getUserByTelegramId(1001);
  assert.deepEqual(idp.ctx.store.getConsents(user.id, 'test-client').map((c) => c.scope), ['openid']);
});

test('state is never reflected unescaped; page has CSP and no-store', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { name: '<img src=x onerror=alert(1)>' });
  const evil = '</script><script>alert(1)</script>"\'';
  const res = await idp.app.inject({ url: authorizeUrl({ code_challenge: challenge, state: evil }) });
  assert.equal(res.statusCode, 200);
  assert.ok(!res.body.includes(evil));
  assert.ok(!res.body.includes('alert(1)</script>'));
  assert.ok(!res.body.includes('<img src=x'));
  assert.ok(res.body.includes('&lt;img src=x onerror=alert(1)&gt;'));
  // The only script is the external one.
  assert.deepEqual(res.body.match(/<script[^>]*>/g), ['<script src="/static/login.js">']);
  assert.match(res.headers['content-security-policy'], /script-src 'self'/);
  assert.match(res.headers['content-security-policy'], /frame-ancestors 'none'/);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.headers['x-frame-options'], 'DENY');

  const js = await idp.app.inject({ url: '/static/login.js' });
  assert.equal(js.statusCode, 200);
  assert.match(js.headers['content-type'], /javascript/);
});

test('status endpoint is bound to the browser session', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { statusUrl, cookie } = await startLogin(idp.app, { code_challenge: challenge });
  assert.equal((await pollStatus(idp.app, statusUrl, cookie)).body.status, 'pending');
  const other = await idp.app.inject({ url: statusUrl, headers: { cookie: '__Host-tgidp_session=0123456789abcdef0123456789abcdef' } });
  assert.equal(other.statusCode, 404);
  const none = await idp.app.inject({ url: statusUrl });
  assert.equal(none.statusCode, 404);
});

test('denial in Telegram sends the browser back with access_denied', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { token, statusUrl, cookie } = await startLogin(idp.app, { code_challenge: challenge, state: 'st' });
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, tgUser());
  assert.ok(idp.ctx.oauth.denyLogin(outcome.authRequestId, tgUser()));
  const { body } = await pollStatus(idp.app, statusUrl, cookie);
  assert.equal(body.status, 'denied');
  const url = new URL(body.redirect_to);
  assert.equal(url.searchParams.get('error'), 'access_denied');
  assert.equal(url.searchParams.get('state'), 'st');
});

test('the first Telegram account to open a link owns it', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { token } = await startLogin(idp.app, { code_challenge: challenge });
  const alice = tgUser();
  const mallory = tgUser({ id: 666, username: 'mallory' });
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, alice);
  assert.equal(outcome.kind, 'consent');
  assert.equal((await idp.ctx.oauth.beginTelegramLogin(token, mallory)).kind, 'invalid');
  // Mallory cannot approve or deny Alice's request either.
  assert.equal(idp.ctx.oauth.approveLogin(outcome.authRequestId, mallory), null);
  assert.equal(idp.ctx.oauth.denyLogin(outcome.authRequestId, mallory), false);
  assert.ok(idp.ctx.oauth.approveLogin(outcome.authRequestId, alice));
});

test('expired auth requests cannot be approved', async () => {
  const idp = await createTestIdp({ config: { authRequestTtl: 60 } });
  await addClient(idp.ctx);
  const { token, statusUrl, cookie } = await startLogin(idp.app, { code_challenge: challenge });
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, tgUser());
  idp.clock.advance(61);
  assert.equal(idp.ctx.oauth.approveLogin(outcome.authRequestId, tgUser()), null);
  assert.equal((await pollStatus(idp.app, statusUrl, cookie)).body.status, 'expired');
});

test('an approved request survives the cleanup sweep until its code is collected', async () => {
  const idp = await createTestIdp({ config: { authRequestTtl: 60, authCodeTtl: 60 } });
  await addClient(idp.ctx);
  const { token, statusUrl, cookie } = await startLogin(idp.app, { code_challenge: challenge });
  idp.clock.advance(50);
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, tgUser());
  idp.ctx.oauth.approveLogin(outcome.authRequestId, tgUser());
  idp.clock.advance(20); // request's own TTL has passed, the code's has not
  idp.ctx.store.deleteExpired(idp.clock.now());
  assert.equal((await pollStatus(idp.app, statusUrl, cookie)).body.status, 'approved');
});
