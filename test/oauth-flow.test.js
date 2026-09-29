import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import {
  REDIRECT_URI, addClient, createTestIdp, exchangeCode, login, tgUser,
} from './helpers.js';

test('end-to-end: authorize → Telegram approval → code → tokens → userinfo', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);

  const { code, verifier, redirectTo } = await login(idp, { state: 's-1', nonce: 'n-1' });
  assert.equal(`${redirectTo.origin}${redirectTo.pathname}`, REDIRECT_URI);
  assert.equal(redirectTo.searchParams.get('state'), 's-1');
  assert.equal(redirectTo.searchParams.get('iss'), 'https://idp.test', 'RFC 9207 iss parameter');

  const res = await exchangeCode(idp.app, { code, verifier });
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['cache-control'], 'no-store');
  const body = res.json();
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.expires_in, 900);
  assert.equal(body.scope, 'openid profile telegram');
  assert.equal(body.refresh_token, undefined, 'no offline_access, no refresh token');

  const idToken = decodeJwt(body.id_token);
  assert.equal(idToken.nonce, 'n-1');
  assert.equal(idToken.aud, 'test-client');
  assert.equal(idToken.iss, 'https://idp.test');
  assert.equal(idToken.preferred_username, 'alice');
  assert.equal(idToken.auth_time, idp.clock.now());

  const header = decodeProtectedHeader(body.access_token);
  assert.equal(header.typ, 'at+jwt');
  assert.ok(header.kid);

  const info = await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${body.access_token}` } });
  assert.equal(info.statusCode, 200);
  assert.deepEqual(info.json(), {
    sub: idToken.sub,
    name: 'Alice Liddell',
    given_name: 'Alice',
    family_name: 'Liddell',
    preferred_username: 'alice',
    locale: 'en',
    telegram_id: 1001,
    telegram_is_premium: false,
  });
});

test('refresh tokens require offline_access unless configured to always issue', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const withOffline = await login(idp, { scope: 'openid offline_access' });
  assert.ok((await exchangeCode(idp.app, withOffline)).json().refresh_token);

  const always = await createTestIdp({ config: { issueRefreshTokens: 'always' } });
  await addClient(always.ctx);
  assert.ok((await exchangeCode(always.app, await login(always))).json().refresh_token);
});

test('token endpoint also accepts JSON bodies', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  const res = await idp.app.inject({
    method: 'POST',
    url: '/token',
    payload: { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT_URI, client_id: 'test-client' },
  });
  assert.equal(res.statusCode, 200);
});

test('scope without openid yields no id_token and userinfo refuses it', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp, { scope: 'telegram' });
  const body = (await exchangeCode(idp.app, { code, verifier })).json();
  assert.equal(body.id_token, undefined);
  const info = await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${body.access_token}` } });
  assert.equal(info.statusCode, 403);
  assert.equal(info.json().error, 'insufficient_scope');
});

test('the login refreshes the stored profile on every sign-in', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  await login(idp, { user: tgUser({ username: 'old' }) });
  await login(idp, { user: tgUser({ username: 'new', is_premium: true, language_code: 'de' }) });
  const row = idp.ctx.store.getUserByTelegramId(1001);
  assert.equal(row.telegram_username, 'new');
  assert.equal(row.is_premium, 1);
  assert.equal(row.language_code, 'de');
  assert.equal(row.last_login_at, idp.clock.now());
});

test('two differently configured instances coexist in one process', async () => {
  const a = await createTestIdp({ config: { issuer: 'https://a.test', accessTokenTtl: '5m' } });
  const b = await createTestIdp({ config: { issuer: 'https://b.test', accessTokenTtl: '1h' } });
  await addClient(a.ctx);
  await addClient(b.ctx);
  const ta = (await exchangeCode(a.app, await login(a))).json();
  const tb = (await exchangeCode(b.app, await login(b))).json();
  assert.equal(ta.expires_in, 300);
  assert.equal(tb.expires_in, 3600);
  assert.equal(decodeJwt(ta.access_token).iss, 'https://a.test');
  assert.equal(decodeJwt(tb.access_token).iss, 'https://b.test');
  // A token from instance A is not accepted by instance B (different issuer).
  const cross = await b.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${ta.access_token}` } });
  assert.equal(cross.statusCode, 401);
});
