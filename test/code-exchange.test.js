import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addClient, createTestIdp, exchangeCode, login, pkce, refreshGrant } from './helpers.js';

test('concurrent exchanges of one code: exactly one succeeds', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  const results = await Promise.all(Array.from({ length: 5 }, () => exchangeCode(idp.app, { code, verifier })));
  assert.equal(results.filter((r) => r.statusCode === 200).length, 1);
  for (const r of results.filter((x) => x.statusCode !== 200)) assert.equal(r.json().error, 'invalid_grant');
});

test('replaying a used code revokes the tokens it produced', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  const tokens = (await exchangeCode(idp.app, { code, verifier })).json();

  const replay = await exchangeCode(idp.app, { code, verifier });
  assert.equal(replay.statusCode, 400);

  assert.equal((await refreshGrant(idp.app, tokens.refresh_token)).statusCode, 400);
  const info = await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(info.statusCode, 401);
});

test('PKCE: a missing code_verifier is invalid_request and does not burn the code', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  const res = await exchangeCode(idp.app, { code, verifier: '' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'invalid_request');
  assert.equal((await exchangeCode(idp.app, { code, verifier })).statusCode, 200);
});

test('PKCE: a wrong verifier fails and burns the code', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  const wrong = await exchangeCode(idp.app, { code, verifier: pkce().verifier });
  assert.equal(wrong.statusCode, 400);
  assert.equal(wrong.json().error, 'invalid_grant');
  assert.equal((await exchangeCode(idp.app, { code, verifier })).statusCode, 400);
});

test('PKCE: a malformed (too short) verifier is rejected', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code } = await login(idp);
  const res = await exchangeCode(idp.app, { code, verifier: 'short' });
  assert.equal(res.json().error, 'invalid_grant');
  assert.match(res.json().error_description, /Malformed/);
});

test('the redirect_uri must match the authorization request exactly', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  const res = await exchangeCode(idp.app, { code, verifier, redirectUri: 'https://client.example.com/callback/' });
  assert.equal(res.json().error, 'invalid_grant');
});

test('a code cannot be redeemed by another client', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  await addClient(idp.ctx, { clientId: 'other-client' });
  const { code, verifier } = await login(idp);
  const res = await exchangeCode(idp.app, { code, verifier, clientId: 'other-client' });
  assert.equal(res.json().error, 'invalid_grant');
});

test('codes expire', async () => {
  const idp = await createTestIdp({ config: { authCodeTtl: 30 } });
  await addClient(idp.ctx);
  const { code, verifier } = await login(idp);
  idp.clock.advance(31);
  assert.equal((await exchangeCode(idp.app, { code, verifier })).json().error, 'invalid_grant');
});

test('unknown client at the token endpoint is invalid_client (401)', async () => {
  const idp = await createTestIdp();
  const res = await exchangeCode(idp.app, { code: 'x', verifier: pkce().verifier, clientId: 'nope' });
  assert.equal(res.statusCode, 401);
  assert.equal(res.json().error, 'invalid_client');
});
