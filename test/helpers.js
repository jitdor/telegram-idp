import crypto from 'crypto';
import { createDatabase } from '../src/db.js';
import { buildApp } from '../src/index.js';

export function createTestDb() {
  return createDatabase(':memory:');
}

export function createTestClient(db, overrides = {}) {
  const client = {
    client_id: overrides.client_id || 'test-client',
    client_secret_hash: overrides.client_secret || null,
    name: 'Test Client',
    redirect_uris: JSON.stringify(['https://client.example.com/callback']),
    allowed_scopes: 'openid profile telegram offline_access',
    policy: null,
    is_first_party: overrides.is_first_party ?? 0,
  };
  db.prepare(`INSERT OR REPLACE INTO oauth_clients
    (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, policy, is_first_party)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(client.client_id, client.client_secret_hash, client.name, client.redirect_uris, client.allowed_scopes, client.policy, client.is_first_party);
  return client;
}

export function createTestUser(db, telegramUser = {}) {
  const user = {
    telegram_user_id: telegramUser.id || 123456789,
    telegram_username: telegramUser.username || 'testuser',
    first_name: telegramUser.first_name || 'Test',
    last_name: telegramUser.last_name || 'User',
    photo_url: null,
  };
  const info = db.prepare('INSERT INTO users (telegram_user_id, telegram_username, first_name, last_name, photo_url) VALUES (?, ?, ?, ?, ?)')
    .run(user.telegram_user_id, user.telegram_username, user.first_name, user.last_name, user.photo_url);
  return db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
}

export function createApprovedAuthRequest(db, user, client, scope = 'openid profile telegram', codeChallenge = 'test-challenge', codeChallengeMethod = 'S256') {
  const authRequestId = crypto.randomBytes(16).toString('hex');
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + 120000;
  db.prepare(`INSERT INTO auth_requests
    (id, token, client_id, redirect_uri, state, scope, nonce, code_challenge, code_challenge_method, status, user_id, browser_session_id, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?)`)
    .run(authRequestId, token, client.client_id, 'https://client.example.com/callback', 'state123', scope, null, codeChallenge, codeChallengeMethod, user.id, 'browser-session-id', expiresAt);
  return { id: authRequestId, token };
}

export function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}