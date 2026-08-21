import { test, before } from 'node:test';
import assert from 'node:assert';
import { createTestDb, createTestClient, createTestUser, createApprovedAuthRequest } from './helpers.js';
import { buildApp } from '../src/index.js';
import { createAuthorizationCode } from '../src/oauth.js';

let db, app, client, user;

before(async () => {
  db = createTestDb();
  client = createTestClient(db, { is_first_party: 1 });
  user = createTestUser(db);
  app = await buildApp({ db, logger: false });
});

test('userinfo rejects id_token (token type)', async () => {
  // Create an id_token directly
  const { createIdToken } = await import('../src/tokens.js');
  const idToken = await createIdToken(user, client.client_id, 'nonce');
  const res = await app.inject({
    method: 'GET',
    url: '/userinfo',
    headers: { authorization: `Bearer ${idToken}` },
  });
  assert.equal(res.statusCode, 401);
});

test('userinfo accepts access token', async () => {
  const { createAccessToken } = await import('../src/tokens.js');
  const accessToken = await createAccessToken(user, client.client_id, 'openid profile telegram');
  const res = await app.inject({
    method: 'GET',
    url: '/userinfo',
    headers: { authorization: `Bearer ${accessToken}` },
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.telegram_id, user.telegram_user_id);
});

test('sweep race: approved auth request survives cleanup', async () => {
  const authReq = createApprovedAuthRequest(db, user, client);
  // Immediately run cleanup (simulate)
  db.prepare('DELETE FROM auth_requests WHERE expires_at < ?').run(Date.now());
  // Poll should still find the auth request and code
  const code = createAuthorizationCode(authReq.id, user.id);
  // Check that code exists and auth request still present
  const row = db.prepare('SELECT * FROM auth_requests WHERE id = ?').get(authReq.id);
  assert.ok(row);
  const codeRow = db.prepare('SELECT * FROM authorization_codes WHERE code = ?').get(code);
  assert.ok(codeRow);
});
