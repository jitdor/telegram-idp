import { transaction } from './db.js';
import { splitScopes } from './util.js';

/** @typedef {import('./types.js').Client} Client */
/** @typedef {import('./types.js').User} User */
/** @typedef {import('./types.js').TelegramUser} TelegramUser */
/** @typedef {import('./types.js').AuthRequestRow} AuthRequestRow */
/** @typedef {import('./types.js').AuthCodeRow} AuthCodeRow */
/** @typedef {import('./types.js').RefreshTokenRow} RefreshTokenRow */
/** @typedef {ReturnType<typeof createSqliteStore>} Store */

/**
 * Persistence for the IdP, as a narrow set of named operations over one
 * SQLite handle. Every state transition that must happen at most once is a
 * single conditional UPDATE whose affected-row count is checked.
 * @param {import('node:sqlite').DatabaseSync} db
 */
export function createSqliteStore(db) {
  /** @type {Map<string, import('node:sqlite').StatementSync>} */
  const cache = new Map();
  const q = (sql) => {
    let stmt = cache.get(sql);
    if (!stmt) {
      stmt = db.prepare(sql);
      cache.set(sql, stmt);
    }
    return stmt;
  };

  /** @returns {Client | null} */
  function toClient(row) {
    if (!row) return null;
    return {
      clientId: row.client_id,
      name: row.name,
      secretHash: row.client_secret_hash || null,
      redirectUris: JSON.parse(row.redirect_uris),
      allowedScopes: splitScopes(row.allowed_scopes),
      policy: row.policy ? JSON.parse(row.policy) : null,
      isFirstParty: row.is_first_party === 1,
    };
  }

  return {
    db,
    /** @template T @param {() => T} fn @returns {T} */
    transaction: (fn) => transaction(db, fn),

    // ---- clients ----

    /** @param {string} clientId */
    getClient(clientId) {
      if (typeof clientId !== 'string') return null;
      return toClient(q('SELECT * FROM oauth_clients WHERE client_id = ?').get(clientId));
    },

    listClients() {
      return q('SELECT * FROM oauth_clients ORDER BY client_id').all().map(toClient);
    },

    /** @param {Client} c @param {number} now */
    upsertClient(c, now) {
      q(`INSERT INTO oauth_clients
          (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, policy, is_first_party, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(client_id) DO UPDATE SET
          client_secret_hash = excluded.client_secret_hash, name = excluded.name,
          redirect_uris = excluded.redirect_uris, allowed_scopes = excluded.allowed_scopes,
          policy = excluded.policy, is_first_party = excluded.is_first_party`)
        .run(c.clientId, c.secretHash, c.name, JSON.stringify(c.redirectUris), c.allowedScopes.join(' '),
          c.policy ? JSON.stringify(c.policy) : null, c.isFirstParty ? 1 : 0, now);
    },

    /** @param {string} clientId */
    deleteClient(clientId) {
      return q('DELETE FROM oauth_clients WHERE client_id = ?').run(clientId).changes > 0;
    },

    /** @param {string} clientId @param {string} hash */
    setClientSecretHash(clientId, hash) {
      q('UPDATE oauth_clients SET client_secret_hash = ? WHERE client_id = ?').run(hash, clientId);
    },

    // ---- users ----

    /**
     * Create or refresh the local profile from a live Telegram `User` object.
     * @param {TelegramUser} tg @param {number} now @returns {User}
     */
    upsertTelegramUser(tg, now) {
      q(`INSERT INTO users
          (telegram_user_id, telegram_username, first_name, last_name, photo_url, language_code, is_premium,
           created_at, updated_at, last_login_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(telegram_user_id) DO UPDATE SET
          telegram_username = excluded.telegram_username, first_name = excluded.first_name,
          last_name = excluded.last_name, photo_url = COALESCE(excluded.photo_url, users.photo_url),
          language_code = excluded.language_code, is_premium = excluded.is_premium,
          updated_at = excluded.updated_at, last_login_at = excluded.last_login_at`)
        .run(tg.id, tg.username ?? null, tg.first_name ?? null, tg.last_name ?? null, tg.photo_url ?? null,
          tg.language_code ?? null, tg.is_premium ? 1 : 0, now, now, now);
      return /** @type {User} */ (q('SELECT * FROM users WHERE telegram_user_id = ?').get(tg.id));
    },

    /** @param {number | string} id @returns {User | null} */
    getUser(id) {
      return /** @type {User} */ (q('SELECT * FROM users WHERE id = ?').get(Number(id))) ?? null;
    },

    /** @param {number} telegramUserId @returns {User | null} */
    getUserByTelegramId(telegramUserId) {
      return /** @type {User} */ (q('SELECT * FROM users WHERE telegram_user_id = ?').get(telegramUserId)) ?? null;
    },

    // ---- auth requests ----

    insertAuthRequest(r) {
      q(`INSERT INTO auth_requests
          (id, token_hash, client_id, redirect_uri, state, scope, nonce, code_challenge, code_challenge_method,
           status, browser_session_id, created_at, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`)
        .run(r.id, r.tokenHash, r.clientId, r.redirectUri, r.state ?? null, r.scope, r.nonce ?? null,
          r.codeChallenge, r.codeChallengeMethod, r.browserSessionId, r.createdAt, r.expiresAt);
    },

    /** @param {string} id @returns {AuthRequestRow | null} */
    getAuthRequest(id) {
      if (typeof id !== 'string') return null;
      return /** @type {any} */ (q('SELECT * FROM auth_requests WHERE id = ?').get(id)) ?? null;
    },

    /** @param {string} tokenHash @param {number} now @returns {AuthRequestRow | null} */
    getPendingAuthRequestByTokenHash(tokenHash, now) {
      return /** @type {any} */ (q(`SELECT * FROM auth_requests WHERE token_hash = ? AND status = 'pending' AND expires_at > ?`)
        .get(tokenHash, now)) ?? null;
    },

    /**
     * Bind a pending request to the first Telegram account that opens it.
     * @returns {boolean} true if `telegramUserId` now owns the request
     */
    claimAuthRequest(id, telegramUserId, now) {
      return q(`UPDATE auth_requests SET telegram_user_id = ?
          WHERE id = ? AND status = 'pending' AND expires_at > ?
            AND (telegram_user_id IS NULL OR telegram_user_id = ?)`)
        .run(telegramUserId, id, now, telegramUserId).changes === 1;
    },

    /**
     * `keepUntil` extends the row's lifetime so the browser can still collect
     * the code even if the request itself would have expired sooner.
     * @returns {boolean}
     */
    markAuthRequestApproved(id, telegramUserId, userId, now, keepUntil) {
      return q(`UPDATE auth_requests SET status = 'approved', user_id = ?, expires_at = MAX(expires_at, ?)
          WHERE id = ? AND status = 'pending' AND telegram_user_id = ? AND expires_at > ?`)
        .run(userId, keepUntil, id, telegramUserId, now).changes === 1;
    },

    /**
     * @param {string} id
     * @param {number | null} telegramUserId when set, only that claimant may deny
     * @returns {boolean}
     */
    markAuthRequestDenied(id, telegramUserId, error, description) {
      const sql = telegramUserId === null
        ? `UPDATE auth_requests SET status = 'denied', error = ?, error_description = ? WHERE id = ? AND status = 'pending'`
        : `UPDATE auth_requests SET status = 'denied', error = ?, error_description = ?
             WHERE id = ? AND status = 'pending' AND telegram_user_id = ?`;
      const args = telegramUserId === null ? [error, description, id] : [error, description, id, telegramUserId];
      return q(sql).run(...args).changes === 1;
    },

    // ---- authorization codes ----

    insertAuthorizationCode(c) {
      q(`INSERT INTO authorization_codes
          (code, auth_request_id, user_id, client_id, redirect_uri, code_challenge, code_challenge_method,
           scope, nonce, auth_time, created_at, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(c.code, c.authRequestId, c.userId, c.clientId, c.redirectUri, c.codeChallenge,
          c.codeChallengeMethod, c.scope, c.nonce ?? null, c.authTime, c.createdAt, c.expiresAt);
    },

    /** @returns {AuthCodeRow | null} */
    getAuthorizationCode(code) {
      if (typeof code !== 'string') return null;
      return /** @type {any} */ (q('SELECT * FROM authorization_codes WHERE code = ?').get(code)) ?? null;
    },

    /** @returns {{ code: string } | null} */
    getUnusedCodeForAuthRequest(authRequestId, now) {
      return /** @type {any} */ (q(`SELECT code FROM authorization_codes
          WHERE auth_request_id = ? AND used_at IS NULL AND expires_at > ?`).get(authRequestId, now)) ?? null;
    },

    /** Atomically consume a code. @returns {boolean} true for exactly one caller */
    markCodeUsed(code, now) {
      return q('UPDATE authorization_codes SET used_at = ? WHERE code = ? AND used_at IS NULL')
        .run(now, code).changes === 1;
    },

    /** Remember what a code was exchanged for, so a replay can revoke it. */
    setCodeIssuedTokens(code, familyId, accessJti, accessExp) {
      q(`UPDATE authorization_codes SET refresh_family_id = ?, access_token_jti = ?, access_token_exp = ?
          WHERE code = ?`).run(familyId, accessJti, accessExp, code);
    },

    // ---- refresh tokens ----

    insertRefreshToken(t) {
      q(`INSERT INTO refresh_tokens
          (token_hash, family_id, user_id, client_id, scope, auth_time, created_at, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(t.tokenHash, t.familyId, t.userId, t.clientId, t.scope, t.authTime ?? null, t.createdAt, t.expiresAt);
    },

    /** @returns {RefreshTokenRow | null} */
    getRefreshTokenByHash(tokenHash) {
      return /** @type {any} */ (q('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash)) ?? null;
    },

    /**
     * Single conditional UPDATE: succeeds for at most one concurrent caller.
     * @returns {boolean}
     */
    markRefreshTokenRotated(tokenHash, clientId, now) {
      return q(`UPDATE refresh_tokens SET rotated_at = ?
          WHERE token_hash = ? AND client_id = ? AND rotated_at IS NULL AND revoked_at IS NULL AND expires_at > ?`)
        .run(now, tokenHash, clientId, now).changes === 1;
    },

    revokeRefreshTokenByHash(tokenHash, clientId, now) {
      return q(`UPDATE refresh_tokens SET revoked_at = ?
          WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL`).run(now, tokenHash, clientId).changes;
    },

    revokeRefreshFamily(familyId, now) {
      return q('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL')
        .run(now, familyId).changes;
    },

    revokeRefreshTokensForGrant(userId, clientId, now) {
      return q('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL')
        .run(now, userId, clientId).changes;
    },

    // ---- consents ----

    /** Record consent; the original grant time is kept for scopes already granted. */
    grantConsent(userId, clientId, scopes, now) {
      const stmt = q('INSERT OR IGNORE INTO consents (user_id, client_id, scope, granted_at) VALUES (?, ?, ?, ?)');
      for (const s of scopes) stmt.run(userId, clientId, s, now);
    },

    /** @returns {{ scope: string, granted_at: number }[]} */
    getConsents(userId, clientId) {
      return /** @type {any} */ (q('SELECT scope, granted_at FROM consents WHERE user_id = ? AND client_id = ?')
        .all(userId, clientId));
    },

    /** @returns {{ client_id: string, name: string, scopes: string, granted_at: number }[]} */
    listConsentedClients(userId) {
      return /** @type {any} */ (q(`SELECT c.client_id, o.name, group_concat(c.scope, ' ') AS scopes,
            min(c.granted_at) AS granted_at
          FROM consents c JOIN oauth_clients o ON o.client_id = c.client_id
          WHERE c.user_id = ? GROUP BY c.client_id, o.name ORDER BY o.name`).all(userId));
    },

    revokeConsent(userId, clientId) {
      return q('DELETE FROM consents WHERE user_id = ? AND client_id = ?').run(userId, clientId).changes;
    },

    // ---- access token denylist ----

    denylistAccessToken(jti, expiresAt) {
      q('INSERT OR IGNORE INTO revoked_access_tokens (jti, expires_at) VALUES (?, ?)').run(jti, expiresAt);
    },

    isAccessTokenDenylisted(jti) {
      return !!q('SELECT 1 FROM revoked_access_tokens WHERE jti = ?').get(jti);
    },

    // ---- housekeeping ----

    /**
     * Rotated refresh tokens are kept until expiry so replays can still be
     * detected; used codes are kept until expiry for the same reason.
     */
    deleteExpired(now) {
      q('DELETE FROM authorization_codes WHERE expires_at < ?').run(now);
      q('DELETE FROM auth_requests WHERE expires_at < ?').run(now);
      q('DELETE FROM refresh_tokens WHERE expires_at < ?').run(now);
      q('DELETE FROM revoked_access_tokens WHERE expires_at < ?').run(now);
    },
  };
}
