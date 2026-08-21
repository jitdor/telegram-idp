import Database from 'better-sqlite3';
import { config } from './config.js';

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  telegram_user_id INTEGER UNIQUE NOT NULL,
  telegram_username TEXT,
  first_name TEXT,
  last_name TEXT,
  photo_url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL, -- JSON array
  allowed_scopes TEXT NOT NULL DEFAULT '["openid","profile","telegram"]',
  policy TEXT -- JSON policy or NULL
);

CREATE TABLE IF NOT EXISTS auth_requests (
  id TEXT PRIMARY KEY,
  token TEXT UNIQUE NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  state TEXT,
  scope TEXT,
  nonce TEXT,
  code_challenge TEXT,
  code_challenge_method TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  user_id INTEGER,
  browser_session_id TEXT,
  reason TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS authorization_codes (
  code TEXT PRIMARY KEY,
  auth_request_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT,
  code_challenge_method TEXT,
  scope TEXT,
  nonce TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(client_id) REFERENCES oauth_clients(client_id)
);

CREATE TABLE IF NOT EXISTS consents (
  user_id INTEGER NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  granted_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, client_id, scope),
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(client_id) REFERENCES oauth_clients(client_id)
);
`);

export default db;
