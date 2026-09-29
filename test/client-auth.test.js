import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashSecret, verifySecret } from '../src/secrets.js';
import { sha256Hex } from '../src/util.js';
import { addClient, basicAuth, createTestIdp, exchangeCode, login, loginAndExchange, refreshGrant } from './helpers.js';

const SECRET = 'correct horse battery staple';

test('secrets are stored as salted scrypt hashes', async () => {
  const a = await hashSecret(SECRET);
  const b = await hashSecret(SECRET);
  assert.match(a, /^scrypt\$32768\$8\$1\$/);
  assert.notEqual(a, b, 'salted');
  assert.deepEqual(await verifySecret(SECRET, a), { ok: true, needsRehash: false });
  assert.equal((await verifySecret('wrong', a)).ok, false);
});

test('client_secret_post and client_secret_basic both work', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { secret: SECRET });

  const post = await login(idp);
  const r1 = await exchangeCode(idp.app, { ...post, extra: { client_secret: SECRET } });
  assert.equal(r1.statusCode, 200);

  const basic = await login(idp);
  const r2 = await idp.app.inject({
    method: 'POST',
    url: '/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basicAuth('test-client', SECRET) },
    payload: new URLSearchParams({
      grant_type: 'authorization_code', code: basic.code, code_verifier: basic.verifier,
      redirect_uri: 'https://client.example.com/callback',
    }).toString(),
  });
  assert.equal(r2.statusCode, 200, r2.body);
});

test('wrong or missing secrets are invalid_client; Basic failures get WWW-Authenticate', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { secret: SECRET });
  const { code, verifier } = await login(idp);

  const missing = await exchangeCode(idp.app, { code, verifier });
  assert.equal(missing.statusCode, 401);
  assert.equal(missing.json().error, 'invalid_client');

  const wrong = await exchangeCode(idp.app, { code, verifier, extra: { client_secret: 'x'.repeat(20) } });
  assert.equal(wrong.statusCode, 401);

  const basic = await idp.app.inject({
    method: 'POST', url: '/token',
    headers: { authorization: basicAuth('test-client', 'nope') },
    payload: { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'https://client.example.com/callback' },
  });
  assert.equal(basic.statusCode, 401);
  assert.match(basic.headers['www-authenticate'], /^Basic/);

  // A failed client authentication never touches the code.
  assert.equal((await exchangeCode(idp.app, { code, verifier, extra: { client_secret: SECRET } })).statusCode, 200);
});

test('using two authentication methods at once is rejected', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx, { secret: SECRET });
  const res = await idp.app.inject({
    method: 'POST', url: '/token',
    headers: { authorization: basicAuth('test-client', SECRET) },
    payload: { grant_type: 'refresh_token', refresh_token: 'x', client_secret: SECRET },
  });
  assert.equal(res.json().error, 'invalid_request');
});

test('public clients must not present a secret', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const tokens = await loginAndExchange(idp);
  const res = await refreshGrant(idp.app, tokens.refresh_token, 'test-client', { client_secret: 'whatever-whatever' });
  assert.equal(res.statusCode, 401);
});

test('legacy unsalted SHA-256 secrets still authenticate and are upgraded to scrypt', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  idp.ctx.store.setClientSecretHash('test-client', sha256Hex(SECRET));
  const { code, verifier } = await login(idp);
  const res = await exchangeCode(idp.app, { code, verifier, extra: { client_secret: SECRET } });
  assert.equal(res.statusCode, 200);
  const stored = idp.ctx.store.getClient('test-client').secretHash;
  assert.match(stored, /^scrypt\$/);
  assert.equal((await verifySecret(SECRET, stored)).ok, true);
});

test('/token is rate limited per IP', async () => {
  const idp = await createTestIdp({ config: { rateLimits: { token: 3 } } });
  const codes = [];
  for (let i = 0; i < 4; i++) {
    const r = await idp.app.inject({ method: 'POST', url: '/token', payload: { grant_type: 'refresh_token', client_id: 'x' } });
    codes.push(r.statusCode);
  }
  assert.deepEqual(codes, [401, 401, 401, 429]);
  idp.clock.advance(61);
  const later = await idp.app.inject({ method: 'POST', url: '/token', payload: { grant_type: 'refresh_token', client_id: 'x' } });
  assert.equal(later.statusCode, 401);
});
