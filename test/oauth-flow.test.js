import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert';
import { createTestDb, createTestClient, createTestUser, createApprovedAuthRequest, pkceChallenge } from './helpers.js';
import { buildApp } from '../src/index.js';
import { createAuthorizationCode, createRefreshToken, validateRefreshToken } from '../src/oauth.js';
import crypto from 'crypto';

let db;
let app;
let client;
let user;

before(async () => {
  db = createTestDb();
  client = createTestClient(db, { is_first_party: 1 });
  user = createTestUser(db);
  app = await buildApp({ db, logger: false });
});

test('full authorization code + PKCE flow', async () => {
  const authReq = createApprovedAuthRequest(db, user, client);
  const code = createAuthorizationCode(authReq.id, user.id);
  // Update code with PKCE challenge
  const verifier = 'test-verifier';
  const challenge = pkceChallenge(verifier);
  db.prepare('UPDATE authorization_codes SET code_challenge = ? WHERE code = ?').run(challenge, code);

  const res = await app.inject({
    method: 'POST',
    url: '/token',
    payload: {
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://client.example.com/callback',
      client_id: client.client_id,
      code_verifier: verifier,
    },
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.ok(body.access_token);
  assert.ok(body.id_token);
  assert.ok(body.refresh_token);
  assert.equal(body.token_type, 'Bearer');
});

test('refresh token flow rotates refresh token', async () => {
  // Create a refresh token manually
  const refreshToken = createRefreshToken(user.id, client.client_id, 'openid profile telegram');
  const res = await app.inject({
    method: 'POST',
    url: '/token',
    payload: {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: client.client_id,
    },
  });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.ok(body.access_token);
  assert.ok(body.refresh_token);
  assert.notEqual(body.refresh_token, refreshToken); // rotated
});

test('old refresh token is invalidated after rotation', async () => {
  const refreshToken = createRefreshToken(user.id, client.client_id, 'openid profile telegram');
  // First use
  await app.inject({
    method: 'POST',
    url: '/token',
    payload: { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: client.client_id },
  });
  // Second use should fail
  const res2 = await app.inject({
    method: 'POST',
    url: '/token',
    payload: { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: client.client_id },
  });
  assert.equal(res2.statusCode, 400);
});
