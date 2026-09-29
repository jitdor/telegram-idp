import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { SCHEMA_VERSION, createDatabase } from '../src/db.js';
import { createSqliteStore } from '../src/store.js';

// Schema as shipped before versioning (datetime('now') text + epoch-millis columns).
const LEGACY_SCHEMA = `
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_user_id INTEGER UNIQUE NOT NULL,
  telegram_username TEXT, first_name TEXT, last_name TEXT, photo_url TEXT,
  created_at TEXT DEFAULT (datetime('now')), last_login_at TEXT);
CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, client_secret_hash TEXT, name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL, allowed_scopes TEXT NOT NULL DEFAULT '["openid","profile","telegram"]',
  policy TEXT, is_first_party INTEGER NOT NULL DEFAULT 0);
CREATE TABLE auth_requests (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL, state TEXT, scope TEXT, nonce TEXT, code_challenge TEXT, code_challenge_method TEXT,
  status TEXT NOT NULL DEFAULT 'pending', user_id INTEGER, browser_session_id TEXT, reason TEXT,
  created_at TEXT DEFAULT (datetime('now')), expires_at INTEGER NOT NULL);
CREATE TABLE authorization_codes (code TEXT PRIMARY KEY, auth_request_id TEXT NOT NULL, user_id INTEGER NOT NULL,
  client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, code_challenge TEXT, code_challenge_method TEXT, scope TEXT,
  nonce TEXT, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE refresh_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL, client_id TEXT NOT NULL, scope TEXT, expires_at INTEGER NOT NULL, rotated_at INTEGER,
  revoked_at INTEGER, created_at TEXT DEFAULT (datetime('now')));
CREATE TABLE consents (user_id INTEGER NOT NULL, client_id TEXT NOT NULL, scope TEXT NOT NULL,
  granted_at TEXT DEFAULT (datetime('now')), PRIMARY KEY (user_id, client_id, scope));
`;

test('an unversioned legacy database is migrated to epoch seconds', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'tgidp-db-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'legacy.db');

  const legacy = new DatabaseSync(file);
  legacy.exec(LEGACY_SCHEMA);
  legacy.exec(`
    INSERT INTO users (telegram_user_id, telegram_username, created_at) VALUES (42, 'bob', '2025-01-02 03:04:05');
    INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris)
      VALUES ('app', '${'a'.repeat(64)}', 'App', '["https://app.test/cb"]');
    INSERT INTO refresh_tokens (token_hash, user_id, client_id, scope, expires_at, rotated_at, created_at)
      VALUES ('h1', 1, 'app', 'openid', 1767225600000, 1735787045000, '2025-01-02 03:04:05');
    INSERT INTO consents (user_id, client_id, scope, granted_at) VALUES (1, 'app', 'openid', '2025-01-02 03:04:05');
    INSERT INTO auth_requests (id, token, client_id, redirect_uri, expires_at) VALUES ('r', 't', 'app', 'x', 1);
  `);
  legacy.close();

  const db = createDatabase(file);
  assert.equal(db.prepare('PRAGMA user_version').get().user_version, SCHEMA_VERSION);
  const store = createSqliteStore(db);

  const user = store.getUserByTelegramId(42);
  assert.equal(user.created_at, Date.UTC(2025, 0, 2, 3, 4, 5) / 1000);
  assert.equal(user.is_premium, 0);
  assert.equal(user.language_code, null);

  const client = store.getClient('app');
  assert.deepEqual(client.allowedScopes, ['openid', 'profile', 'telegram']);
  assert.equal(client.secretHash, 'a'.repeat(64), 'legacy hash kept for upgrade-on-use');

  const rt = store.getRefreshTokenByHash('h1');
  assert.equal(rt.expires_at, 1767225600);
  assert.equal(rt.rotated_at, 1735787045);
  assert.equal(rt.family_id, 'legacy-1');

  assert.equal(store.getConsents(1, 'app')[0].granted_at, Date.UTC(2025, 0, 2, 3, 4, 5) / 1000);
  assert.equal(db.prepare('SELECT count(*) AS n FROM auth_requests').get().n, 0, 'in-flight requests dropped');
  db.close();

  // Re-opening is a no-op.
  createDatabase(file).close();
});

test('a database from a newer build is refused', async (t) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'tgidp-db-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'future.db');
  const future = new DatabaseSync(file);
  future.exec(`PRAGMA user_version = ${SCHEMA_VERSION + 1}`);
  future.close();
  assert.throws(() => createDatabase(file), /newer than this build/);
});
