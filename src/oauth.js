import crypto from 'crypto';
import db from './db.js';
import { config } from './config.js';

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

export function createAuthRequest({ clientId, redirectUri, state, scope, nonce, codeChallenge, codeChallengeMethod, browserSessionId }) {
  const id = randomToken(16);
  const token = randomToken(32);
  const expiresAt = Date.now() + config.authRequestTtl * 1000;
  db.prepare(`INSERT INTO auth_requests
    (id, token, client_id, redirect_uri, state, scope, nonce, code_challenge, code_challenge_method, status, browser_session_id, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`).run(
    id, token, clientId, redirectUri, state, scope, nonce, codeChallenge, codeChallengeMethod, browserSessionId, expiresAt
  );
  return { id, token };
}

export function getAuthRequestByToken(token) {
  return db.prepare('SELECT * FROM auth_requests WHERE token = ? AND status = ? AND expires_at > ?')
    .get(token, 'pending', Date.now());
}

export function getAuthRequestById(id) {
  return db.prepare('SELECT * FROM auth_requests WHERE id = ?').get(id);
}

export function approveAuthRequest(id, telegramUser) {
  let user = db.prepare('SELECT * FROM users WHERE telegram_user_id = ?').get(telegramUser.id);
  if (!user) {
    const info = db.prepare('INSERT INTO users (telegram_user_id, telegram_username, first_name, last_name, photo_url) VALUES (?, ?, ?, ?, ?)')
      .run(telegramUser.id, telegramUser.username, telegramUser.first_name, telegramUser.last_name, telegramUser.photo_url);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  }
  const authRequest = getAuthRequestById(id);
  if (!authRequest || authRequest.status !== 'pending') return null;

  db.prepare('INSERT OR IGNORE INTO consents (user_id, client_id, scope) VALUES (?, ?, ?)')
    .run(user.id, authRequest.client_id, authRequest.scope);
  db.prepare('UPDATE auth_requests SET status = ?, user_id = ? WHERE id = ?').run('approved', user.id, id);
  createAuthorizationCode(id, user.id);
  return user;
}

export function denyAuthRequest(id, reason = null) {
  const authRequest = getAuthRequestById(id);
  if (!authRequest || authRequest.status !== 'pending') return false;
  db.prepare('UPDATE auth_requests SET status = ?, reason = ? WHERE id = ?').run('denied', reason, id);
  return true;
}

// ---- Authorization code store (DB-backed) ----

export function createAuthorizationCode(authRequestId, userId) {
  const authRequest = getAuthRequestById(authRequestId);
  const code = randomToken(32);
  const expiresAt = Date.now() + 60_000;
  db.prepare(`INSERT INTO authorization_codes
    (code, auth_request_id, user_id, client_id, redirect_uri, code_challenge, code_challenge_method, scope, nonce, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(
      code,
      authRequestId,
      userId,
      authRequest.client_id,
      authRequest.redirect_uri,
      authRequest.code_challenge,
      authRequest.code_challenge_method,
      authRequest.scope,
      authRequest.nonce,
      expiresAt
    );
  return code;
}

export function consumeAuthorizationCode(code, redirectUri, clientId, codeVerifier) {
  const row = db.prepare('SELECT * FROM authorization_codes WHERE code = ? AND used = 0').get(code);
  if (!row) return null;
  if (row.expires_at < Date.now()) return null;
  if (row.redirect_uri !== redirectUri || row.client_id !== clientId) return null;
  if (row.code_challenge) {
    const expected = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    if (expected !== row.code_challenge) return null;
  }
  db.prepare('UPDATE authorization_codes SET used = 1 WHERE code = ?').run(code);
  return {
    userId: row.user_id,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    scope: row.scope,
    nonce: row.nonce,
  };
}

export function hasConsent(userId, clientId, scope) {
  const row = db.prepare('SELECT 1 FROM consents WHERE user_id = ? AND client_id = ? AND scope = ?').get(userId, clientId, scope);
  return !!row;
}
