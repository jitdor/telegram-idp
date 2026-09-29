import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  addClient, basicAuth, createTestIdp, fakeTelegram, login, loginAndExchange, postForm, refreshGrant,
} from './helpers.js';

test('discovery advertises what is implemented', async () => {
  const idp = await createTestIdp();
  const doc = (await idp.app.inject({ url: '/.well-known/openid-configuration' })).json();
  assert.equal(doc.issuer, 'https://idp.test');
  assert.deepEqual(doc.grant_types_supported, ['authorization_code', 'refresh_token']);
  assert.deepEqual(doc.token_endpoint_auth_methods_supported, ['none', 'client_secret_basic', 'client_secret_post']);
  assert.equal(doc.revocation_endpoint, 'https://idp.test/revoke');
  assert.equal(doc.introspection_endpoint, 'https://idp.test/introspect');
  assert.equal(doc.authorization_response_iss_parameter_supported, true);
  assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
});

test('errors are uniform JSON', async () => {
  const idp = await createTestIdp();
  const notFound = await idp.app.inject({ url: '/nope' });
  assert.equal(notFound.statusCode, 404);
  assert.deepEqual(notFound.json(), { error: 'not_found' });

  const noGrant = await postForm(idp.app, '/token', {});
  assert.equal(noGrant.statusCode, 400);
  assert.equal(noGrant.json().error, 'invalid_request');
  assert.equal(noGrant.headers['cache-control'], 'no-store');

  const dup = await idp.app.inject({
    method: 'POST', url: '/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: 'grant_type=refresh_token&grant_type=authorization_code',
  });
  assert.equal(dup.json().error, 'invalid_request');

  const noBearer = await idp.app.inject({ url: '/userinfo' });
  assert.equal(noBearer.statusCode, 401);
  assert.match(noBearer.headers['www-authenticate'], /^Bearer/);
});

test('introspection: own tokens only, reports active state', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  await addClient(idp.ctx, { clientId: 'other-client' });
  const tokens = await loginAndExchange(idp);

  const at = (await postForm(idp.app, '/introspect', { token: tokens.access_token, client_id: 'test-client' })).json();
  assert.equal(at.active, true);
  assert.equal(at.client_id, 'test-client');
  assert.equal(at.scope, 'openid profile telegram offline_access');
  assert.equal(at.telegram_id, 1001);

  const rt = (await postForm(idp.app, '/introspect', { token: tokens.refresh_token, client_id: 'test-client' })).json();
  assert.equal(rt.active, true);
  assert.equal(rt.token_type, 'refresh_token');

  const foreign = (await postForm(idp.app, '/introspect', { token: tokens.access_token, client_id: 'other-client' })).json();
  assert.deepEqual(foreign, { active: false });
  assert.deepEqual((await postForm(idp.app, '/introspect', { token: 'garbage', client_id: 'test-client' })).json(), { active: false });

  const unauth = await postForm(idp.app, '/introspect', { token: tokens.access_token });
  assert.equal(unauth.statusCode, 401);
});

test('introspection re-evaluates the client policy live', async () => {
  const telegram = fakeTelegram({ '-100:1001': 'member' });
  const idp = await createTestIdp({ telegram });
  await addClient(idp.ctx, { secret: 'resource-server-secret', policy: { type: 'group_membership', chat_id: -100 } });
  const { code, verifier } = await login(idp);
  const tokens = (await postForm(idp.app, '/token', {
    grant_type: 'authorization_code', code, code_verifier: verifier,
    redirect_uri: 'https://client.example.com/callback',
  }, { authorization: basicAuth('test-client', 'resource-server-secret') })).json();

  const introspect = () => postForm(idp.app, '/introspect', { token: tokens.access_token },
    { authorization: basicAuth('test-client', 'resource-server-secret') });
  assert.equal((await introspect()).json().active, true);
  telegram.members['-100:1001'] = 'kicked';
  assert.equal((await introspect()).json().active, false);
});

test('revocation: refresh token family and access token jti', async () => {
  const idp = await createTestIdp();
  await addClient(idp.ctx);
  const tokens = await loginAndExchange(idp);
  const rotated = (await refreshGrant(idp.app, tokens.refresh_token)).json();

  const r1 = await postForm(idp.app, '/revoke', { token: rotated.refresh_token, client_id: 'test-client' });
  assert.equal(r1.statusCode, 200);
  assert.equal((await refreshGrant(idp.app, rotated.refresh_token)).statusCode, 400);

  const r2 = await postForm(idp.app, '/revoke', { token: rotated.access_token, client_id: 'test-client' });
  assert.equal(r2.statusCode, 200);
  const info = await idp.app.inject({ url: '/userinfo', headers: { authorization: `Bearer ${rotated.access_token}` } });
  assert.equal(info.statusCode, 401);

  // Unknown tokens are fine (RFC 7009).
  assert.equal((await postForm(idp.app, '/revoke', { token: 'unknown', client_id: 'test-client' })).statusCode, 200);
});

test('telegram webhook requires the secret header', async () => {
  const updates = [];
  const idp = await createTestIdp({
    config: { telegramWebhookSecret: 'webhook-secret-123456' },
    bot: { handleUpdate: async (u) => { updates.push(u); } },
  });
  const bad = await idp.app.inject({ method: 'POST', url: '/telegram-webhook', payload: { update_id: 1 } });
  assert.equal(bad.statusCode, 403);
  const wrong = await idp.app.inject({
    method: 'POST', url: '/telegram-webhook', payload: { update_id: 1 },
    headers: { 'x-telegram-bot-api-secret-token': 'webhook-secret-12345X' },
  });
  assert.equal(wrong.statusCode, 403);
  const ok = await idp.app.inject({
    method: 'POST', url: '/telegram-webhook', payload: { update_id: 2 },
    headers: { 'x-telegram-bot-api-secret-token': 'webhook-secret-123456' },
  });
  assert.equal(ok.statusCode, 200);
  assert.deepEqual(updates, [{ update_id: 2 }]);
});
