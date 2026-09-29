import { test } from 'node:test';
import assert from 'node:assert/strict';
import { addClient, createTestIdp, fakeTelegram, loginAndExchange, refreshGrant } from './helpers.js';

test('refresh rotates the token and issues a new access token', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const first = await loginAndExchange(idp);
  const res = await refreshGrant(idp.app, first.refresh_token);
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.ok(body.access_token);
  assert.ok(body.id_token);
  assert.notEqual(body.refresh_token, first.refresh_token);
  // The rotated token keeps working.
  assert.equal((await refreshGrant(idp.app, body.refresh_token)).statusCode, 200);
});

test('replaying a rotated refresh token revokes the whole grant', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const first = await loginAndExchange(idp);
  const second = (await refreshGrant(idp.app, first.refresh_token)).json();

  const replay = await refreshGrant(idp.app, first.refresh_token);
  assert.equal(replay.statusCode, 400);
  assert.equal(replay.json().error, 'invalid_grant');

  // The legitimate successor was revoked too: the leak is contained.
  const after = await refreshGrant(idp.app, second.refresh_token);
  assert.equal(after.statusCode, 400);
});

test('reuse detection covers every token family of the user/client pair', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const sessionA = await loginAndExchange(idp);
  const sessionB = await loginAndExchange(idp);
  await refreshGrant(idp.app, sessionA.refresh_token);
  await refreshGrant(idp.app, sessionA.refresh_token); // replay
  assert.equal((await refreshGrant(idp.app, sessionB.refresh_token)).statusCode, 400);
});

test('concurrent refreshes of the same token: exactly one succeeds', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const first = await loginAndExchange(idp);
  const results = await Promise.all(Array.from({ length: 5 }, () => refreshGrant(idp.app, first.refresh_token)));
  const ok = results.filter((r) => r.statusCode === 200);
  assert.equal(ok.length, 1);
  assert.ok(results.filter((r) => r.statusCode === 400).length === 4);
  // The race is treated as a replay, so even the winner's token is revoked.
  assert.equal((await refreshGrant(idp.app, ok[0].json().refresh_token)).statusCode, 400);
});

test('a refresh token is bound to its client', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  await addClient(idp.ctx, { clientId: 'other-client' });
  const first = await loginAndExchange(idp);
  const res = await refreshGrant(idp.app, first.refresh_token, 'other-client');
  assert.equal(res.statusCode, 400);
  // …and the failed attempt did not consume it.
  assert.equal((await refreshGrant(idp.app, first.refresh_token)).statusCode, 200);
});

test('refresh tokens expire', async () => {
  const idp = await createTestIdp({ config: { refreshTokenTtl: '1h' } });
  await addClient(idp.ctx);
  const first = await loginAndExchange(idp);
  idp.clock.advance(3601);
  assert.equal((await refreshGrant(idp.app, first.refresh_token)).statusCode, 400);
});

test('refresh may narrow but not widen scope', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const first = await loginAndExchange(idp, { scope: 'openid profile offline_access' });
  const narrowed = await refreshGrant(idp.app, first.refresh_token, 'test-client', { scope: 'openid' });
  assert.equal(narrowed.statusCode, 200);
  assert.equal(narrowed.json().scope, 'openid');
  const widened = await refreshGrant(idp.app, narrowed.json().refresh_token, 'test-client', { scope: 'openid telegram' });
  assert.equal(widened.json().error, 'invalid_scope');
  // The rejected request did not consume the token.
  assert.equal((await refreshGrant(idp.app, narrowed.json().refresh_token)).statusCode, 200);
});

test('with a grace window, a concurrent double refresh fails without logging the user out', async () => {
  const logs = [];
  const record = (level) => (obj, msg) => logs.push({ level, msg, ...obj });
  const logger = { info: record('info'), warn: record('warn'), error: record('error') };
  const idp = await createTestIdp({ config: { refreshReuseGraceSeconds: 10 }, logger });
  await addClient(idp.ctx);
  const first = await loginAndExchange(idp);
  const results = await Promise.all([refreshGrant(idp.app, first.refresh_token), refreshGrant(idp.app, first.refresh_token)]);
  const ok = results.filter((r) => r.statusCode === 200);
  assert.equal(ok.length, 1);
  // The winner's successor survives the race…
  assert.equal((await refreshGrant(idp.app, ok[0].json().refresh_token)).statusCode, 200);
  // The race is logged at info, distinguishable from a theft signal.
  assert.deepEqual(logs.map((l) => l.level), ['info']);
  assert.match(logs[0].msg, /grace window/);
  assert.equal(logs[0].clientId, 'test-client');

  // …but a replay after the window is still treated as theft, and logged as such.
  idp.clock.advance(11);
  assert.equal((await refreshGrant(idp.app, first.refresh_token)).statusCode, 400);
  assert.equal(logs.at(-1).level, 'warn');
  assert.match(logs.at(-1).msg, /reuse detected/);
});

test('policy is re-evaluated on refresh: leaving the group ends the session', async () => {
  const telegram = fakeTelegram({ '-100:1001': 'member' });
  const idp = await createTestIdp({ telegram });
  await addClient(idp.ctx, { policy: { type: 'group_membership', chat_id: -100 } });
  const first = await loginAndExchange(idp);
  const ok = await refreshGrant(idp.app, first.refresh_token);
  assert.equal(ok.statusCode, 200);

  telegram.members['-100:1001'] = 'left';
  const denied = await refreshGrant(idp.app, ok.json().refresh_token);
  assert.equal(denied.statusCode, 400);
  assert.match(denied.json().error_description, /policy/);
});

test('missing refresh_token is invalid_request; unknown grant type is rejected', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const missing = await refreshGrant(idp.app, '');
  assert.equal(missing.json().error, 'invalid_request');
  const res = await idp.app.inject({ method: 'POST', url: '/token', payload: { grant_type: 'password', client_id: 'test-client' } });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().error, 'unsupported_grant_type');
});
