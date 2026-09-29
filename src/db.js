import { DatabaseSync } from 'node:sqlite';
import { splitScopes } from './util.js';

/** Current schema version, stored in `PRAGMA user_version`. */
export const SCHEMA_VERSION = 1;

// All timestamps are INTEGER epoch seconds and are always supplied by the
// application (there are no SQL defaults), so the injected clock is authoritative.
const SCHEMA_V1 = `
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_user_id INTEGER UNIQUE NOT NULL,
  telegram_username TEXT,
  first_name TEXT,
  last_name TEXT,
  photo_url TEXT,
  language_code TEXT,
  is_premium INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  allowed_scopes TEXT NOT NULL,
  policy TEXT,
  is_first_party INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE auth_requests (
  id TEXT PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  state TEXT,
  scope TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  status TEXT NOT NULL,
  telegram_user_id INTEGER,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  browser_session_id TEXT NOT NULL,
  error TEXT,
  error_description TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE authorization_codes (
  code TEXT PRIMARY KEY,
  auth_request_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  auth_time INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  refresh_family_id TEXT,
  access_token_jti TEXT,
  access_token_exp INTEGER
);
CREATE INDEX idx_codes_auth_request ON authorization_codes(auth_request_id);

CREATE TABLE refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT UNIQUE NOT NULL,
  family_id TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  auth_time INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  rotated_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX idx_refresh_user_client ON refresh_tokens(user_id, client_id);
CREATE INDEX idx_refresh_family ON refresh_tokens(family_id);

CREATE TABLE consents (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  scope TEXT NOT NULL,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, client_id, scope)
);

CREATE TABLE revoked_access_tokens (
  jti TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
`;

/**
 * Open (or create) a database and bring its schema up to date.
 * Nothing is opened at import time; callers own the handle.
 * @param {string} [dbPath]
 * @param {{ now?: () => number }} [options]
 */
export function createDatabase(dbPath = ':memory:', options = {}) {
  const db = new DatabaseSync(dbPath);
  if (dbPath !== ':memory:') db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA busy_timeout = 5000');
  migrate(db, options.now ?? (() => Math.floor(Date.now() / 1000)));
  db.exec('PRAGMA foreign_keys = ON');
  return db;
}

/**
 * Run `fn` inside `BEGIN IMMEDIATE … COMMIT`, rolling back on throw.
 * IMMEDIATE takes the write lock up front so concurrent processes serialize.
 * @template T
 * @param {DatabaseSync} db
 * @param {() => T} fn
 * @returns {T}
 */
export function transaction(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function tableColumns(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

/** @param {DatabaseSync} db @param {() => number} now */
function migrate(db, now) {
  const version = Number(db.prepare('PRAGMA user_version').get().user_version);
  if (version === SCHEMA_VERSION) return;
  if (version > SCHEMA_VERSION) {
    throw new Error(`Database schema v${version} is newer than this build supports (v${SCHEMA_VERSION})`);
  }
  const hasLegacyTables = tableColumns(db, 'users').length > 0;
  db.exec('PRAGMA foreign_keys = OFF');
  transaction(db, () => {
    if (hasLegacyTables) migrateFromLegacy(db, now());
    else db.exec(SCHEMA_V1);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  });
}

const LEGACY_TABLES = ['users', 'oauth_clients', 'auth_requests', 'authorization_codes', 'refresh_tokens', 'consents'];

/**
 * v0 (unversioned) → v1: mixed `datetime('now')` text / epoch-millis columns
 * become epoch seconds, users gain premium/language columns, refresh tokens
 * gain a family id. In-flight auth requests and codes (≤ 2 min lifetime) are dropped.
 */
function migrateFromLegacy(db, now) {
  const present = LEGACY_TABLES.filter((t) => tableColumns(db, t).length > 0);
  for (const t of present) db.exec(`ALTER TABLE ${t} RENAME TO legacy_${t}`);
  db.exec(SCHEMA_V1);

  const textToEpoch = (v) => {
    if (v === null || v === undefined) return null;
    if (typeof v === 'number') return v > 1e11 ? Math.floor(v / 1000) : v;
    const ms = Date.parse(String(v).replace(' ', 'T') + (String(v).includes('Z') ? '' : 'Z'));
    return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
  };
  const msToEpoch = (v) => (v === null || v === undefined ? null : Math.floor(Number(v) / 1000));

  if (present.includes('users')) {
    const insert = db.prepare(`INSERT INTO users
      (id, telegram_user_id, telegram_username, first_name, last_name, photo_url, is_premium, created_at, updated_at, last_login_at)
      VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)`);
    for (const u of db.prepare('SELECT * FROM legacy_users').all()) {
      const created = textToEpoch(u.created_at) ?? now;
      insert.run(u.id, u.telegram_user_id, u.telegram_username, u.first_name, u.last_name, u.photo_url,
        created, created, textToEpoch(u.last_login_at));
    }
  }

  if (present.includes('oauth_clients')) {
    const insert = db.prepare(`INSERT INTO oauth_clients
      (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, policy, is_first_party, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const c of db.prepare('SELECT * FROM legacy_oauth_clients').all()) {
      insert.run(c.client_id, c.client_secret_hash, c.name, c.redirect_uris,
        splitScopes(c.allowed_scopes).join(' '), c.policy, c.is_first_party ?? 0, now);
    }
  }

  if (present.includes('refresh_tokens')) {
    const insert = db.prepare(`INSERT INTO refresh_tokens
      (id, token_hash, family_id, user_id, client_id, scope, created_at, expires_at, rotated_at, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const r of db.prepare('SELECT * FROM legacy_refresh_tokens').all()) {
      insert.run(r.id, r.token_hash, `legacy-${r.id}`, r.user_id, r.client_id, r.scope || '',
        textToEpoch(r.created_at) ?? now, msToEpoch(r.expires_at), msToEpoch(r.rotated_at), msToEpoch(r.revoked_at));
    }
  }

  if (present.includes('consents')) {
    const insert = db.prepare('INSERT INTO consents (user_id, client_id, scope, granted_at) VALUES (?, ?, ?, ?)');
    for (const c of db.prepare('SELECT * FROM legacy_consents').all()) {
      insert.run(c.user_id, c.client_id, c.scope, textToEpoch(c.granted_at) ?? now);
    }
  }

  for (const t of present) db.exec(`DROP TABLE legacy_${t}`);
}
