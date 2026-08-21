import { test, before } from 'node:test';
import assert from 'node:assert';
import { createTestDb, createTestClient, createTestUser } from './helpers.js';
import { hasConsent, approveAuthRequest, createAuthRequest, setDb } from '../src/oauth.js';

let db, client, user;

before(() => {
  db = createTestDb();
  setDb(db); // <-- ensure OAuth functions use the test DB
  client = createTestClient(db, { is_first_party: 1 });
  user = createTestUser(db);
});

test('consent storage and retrieval uses internal user ID', () => {
  const authReq = createAuthRequest({
    clientId: client.client_id,
    redirectUri: 'https://client.example.com/callback',
    state: 'test-state',
    scope: 'openid profile telegram',
    nonce: null,
    codeChallenge: 'test-challenge',
    codeChallengeMethod: 'S256',
    browserSessionId: 'test-session',
  });

  const telegramUser = {
    id: user.telegram_user_id,
    username: user.telegram_username,
    first_name: user.first_name,
    last_name: user.last_name,
    photo_url: user.photo_url,
  };
  const approvedUser = approveAuthRequest(authReq.id, telegramUser);
  assert.ok(approvedUser);

  const has = hasConsent(user.id, client.client_id, 'openid');
  assert.ok(has);

  const wrongHas = hasConsent(user.telegram_user_id, client.client_id, 'openid');
  assert.equal(wrongHas, false);
});