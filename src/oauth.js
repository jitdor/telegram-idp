import { DEFAULT_SCOPES } from './config.js';
import { OAuthError, UnsafeRedirectError, invalidClient, invalidGrant, invalidRequest, invalidToken } from './errors.js';
import { evaluatePolicy } from './policy.js';
import { hashSecret, verifySecret } from './secrets.js';
import { profileClaims } from './tokens.js';
import { randomToken, safeEqual, sha256Base64url, sha256Hex, splitScopes } from './util.js';

/** @typedef {import('./types.js').IdpContext} IdpContext */
/** @typedef {import('./types.js').Client} Client */
/** @typedef {import('./types.js').User} User */
/** @typedef {import('./types.js').TelegramUser} TelegramUser */
/** @typedef {ReturnType<typeof createOAuthService>} OAuthService */

const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const PKCE_VERIFIER = /^[A-Za-z0-9._~-]{43,128}$/;

/**
 * Append parameters to a registered redirect URI, keeping its own query.
 * Always adds `iss` (RFC 9207) so clients can detect IdP mix-up.
 * @param {string} redirectUri
 * @param {Record<string, string | null | undefined>} params
 * @param {string} issuer
 */
export function buildRedirect(redirectUri, params, issuer) {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null) url.searchParams.set(k, v);
  }
  url.searchParams.set('iss', issuer);
  return url.toString();
}

/** Policy subject from a persisted profile (used after login, when no live update exists). */
function subjectFromUser(user) {
  return {
    id: user.telegram_user_id,
    username: user.telegram_username ?? undefined,
    is_premium: user.is_premium === 1,
    language_code: user.language_code ?? undefined,
  };
}

/**
 * Transport-agnostic OAuth 2.0 / OIDC logic. The Fastify routes and grammY
 * handlers are thin adapters over this.
 * @param {Omit<IdpContext, 'oauth'>} ctx
 */
export function createOAuthService(ctx) {
  const { config, store, tokens, clock, logger } = ctx;
  const redirect = (uri, params) => buildRedirect(uri, params, config.issuer);

  /** Query parameters must appear at most once (RFC 6749 §3.1). */
  function single(query, name, ErrorType = OAuthError) {
    const v = query[name];
    if (v === undefined || v === '') return undefined;
    if (typeof v !== 'string') throw new ErrorType('invalid_request', `${name} must be provided once`);
    return v;
  }

  // ---------------------------------------------------------------------------
  // Authorization endpoint
  // ---------------------------------------------------------------------------

  /**
   * Validate an authorization request and start a Telegram login.
   * Errors about the client or redirect URI throw `UnsafeRedirectError`
   * (render locally); everything else is returned as a redirect to the client.
   * @param {Record<string, unknown>} query
   * @param {string} browserSessionId
   * @returns {Promise<{ kind: 'login', authRequestId: string, deepLink: string, expiresAt: number, client: Client }
   *   | { kind: 'redirect', location: string }>}
   */
  async function authorize(query, browserSessionId) {
    const clientId = single(query, 'client_id', UnsafeRedirectError);
    const redirectUri = single(query, 'redirect_uri', UnsafeRedirectError);
    const client = clientId ? store.getClient(clientId) : null;
    if (!client) throw new UnsafeRedirectError('invalid_client', 'Unknown client_id');
    // Exact string match against the registered list (no normalization, no prefix matching).
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      throw new UnsafeRedirectError('invalid_request', 'redirect_uri is not registered for this client');
    }
    const rawState = query.state;
    const state = typeof rawState === 'string' ? rawState : undefined;

    try {
      if (single(query, 'response_type') !== 'code') {
        throw new OAuthError('unsupported_response_type', 'Only response_type=code is supported');
      }
      if (rawState !== undefined && typeof rawState !== 'string') throw invalidRequest('state must be provided once');
      const codeChallenge = single(query, 'code_challenge');
      const method = single(query, 'code_challenge_method');
      if (!codeChallenge) throw invalidRequest('PKCE code_challenge is required');
      if (method !== 'S256') throw invalidRequest('code_challenge_method must be S256');
      if (!PKCE_CHALLENGE.test(codeChallenge)) throw invalidRequest('Malformed code_challenge');

      const requested = single(query, 'scope');
      const scopes = requested
        ? splitScopes(requested)
        : DEFAULT_SCOPES.filter((s) => client.allowedScopes.includes(s));
      const denied = scopes.filter((s) => !client.allowedScopes.includes(s));
      if (denied.length) throw new OAuthError('invalid_scope', `Scope not allowed for this client: ${denied.join(' ')}`);
      if (scopes.length === 0) throw new OAuthError('invalid_scope', 'No scope requested');

      const prompt = single(query, 'prompt');
      if (prompt && prompt.split(' ').includes('none')) {
        throw new OAuthError('login_required', 'Interactive Telegram approval is always required');
      }

      const botUsername = ctx.getBotUsername();
      if (!botUsername) throw new OAuthError('temporarily_unavailable', 'Telegram bot is not ready');

      const now = clock.now();
      const id = randomToken(16);
      const token = randomToken(32);
      const expiresAt = now + config.authRequestTtl;
      store.insertAuthRequest({
        id,
        tokenHash: sha256Hex(token),
        clientId: client.clientId,
        redirectUri,
        state,
        scope: scopes.join(' '),
        nonce: single(query, 'nonce'),
        codeChallenge,
        codeChallengeMethod: method,
        browserSessionId,
        createdAt: now,
        expiresAt,
      });
      return {
        kind: 'login',
        authRequestId: id,
        deepLink: `https://t.me/${botUsername}?start=auth_${token}`,
        expiresAt,
        client,
      };
    } catch (err) {
      if (!(err instanceof OAuthError)) throw err;
      return {
        kind: 'redirect',
        location: redirect(redirectUri, { error: err.error, error_description: err.description, state }),
      };
    }
  }

  /**
   * What the waiting browser should do next. Only the browser that started
   * the request (same session cookie) may see its outcome.
   * @param {string} id
   * @param {string | undefined} browserSessionId
   */
  function getAuthRequestStatus(id, browserSessionId) {
    const r = store.getAuthRequest(id);
    if (!r || !browserSessionId || !safeEqual(r.browser_session_id, browserSessionId)) return null;
    const now = clock.now();
    if (r.status === 'approved') {
      const row = store.getUnusedCodeForAuthRequest(id, now);
      if (!row) return { status: 'expired' };
      return { status: 'approved', redirect_to: redirect(r.redirect_uri, { code: row.code, state: r.state }) };
    }
    if (r.status === 'denied') {
      return {
        status: 'denied',
        redirect_to: redirect(r.redirect_uri, {
          error: r.error || 'access_denied',
          error_description: r.error_description,
          state: r.state,
        }),
      };
    }
    if (r.expires_at <= now) return { status: 'expired' };
    return { status: 'pending' };
  }

  // ---------------------------------------------------------------------------
  // Telegram side (called by the bot adapter)
  // ---------------------------------------------------------------------------

  function hasConsent(userId, clientId, scopes) {
    const granted = new Set(store.getConsents(userId, clientId).map((c) => c.scope));
    return scopes.length > 0 && scopes.every((s) => granted.has(s));
  }

  /**
   * Handle a deep-link `/start auth_<token>`. Binds the request to the
   * Telegram account, evaluates the client's policy against the *live*
   * Telegram user object, and decides whether consent is needed.
   * @param {string} token
   * @param {TelegramUser} tgUser
   * @returns {Promise<{ kind: 'invalid' }
   *   | { kind: 'denied', reason: string, client: Client }
   *   | { kind: 'approved', client: Client }
   *   | { kind: 'consent', authRequestId: string, client: Client, scopes: string[] }>}
   */
  async function beginTelegramLogin(token, tgUser) {
    if (typeof token !== 'string' || !token || !tgUser?.id) return { kind: 'invalid' };
    const now = clock.now();
    const r = store.getPendingAuthRequestByTokenHash(sha256Hex(token), now);
    // First account to open the link owns it; nobody else can approve it.
    if (!r || !store.claimAuthRequest(r.id, tgUser.id, now)) return { kind: 'invalid' };
    const client = store.getClient(r.client_id);
    if (!client) {
      store.markAuthRequestDenied(r.id, tgUser.id, 'server_error', 'Client no longer exists');
      return { kind: 'invalid' };
    }
    const result = await evaluatePolicy(client.policy, tgUser, ctx.telegram);
    if (!result.pass) {
      // The reason (group ids etc.) is shown to the user in Telegram only, never sent to the client.
      store.markAuthRequestDenied(r.id, tgUser.id, 'access_denied',
        'The user does not meet the requirements of this application');
      return { kind: 'denied', reason: result.reason || 'Policy denied', client };
    }
    const scopes = splitScopes(r.scope);
    const existing = store.getUserByTelegramId(tgUser.id);
    if (client.isFirstParty && existing && hasConsent(existing.id, client.clientId, scopes)) {
      if (approveLogin(r.id, tgUser)) return { kind: 'approved', client };
      return { kind: 'invalid' };
    }
    return { kind: 'consent', authRequestId: r.id, client, scopes };
  }

  /**
   * The claimant approved: persist the profile (including Premium status and
   * language), record consent for exactly the requested scopes, mint a code.
   * @param {string} authRequestId
   * @param {TelegramUser} tgUser
   * @returns {{ client: Client, user: User } | null}
   */
  function approveLogin(authRequestId, tgUser) {
    const now = clock.now();
    return store.transaction(() => {
      const r = store.getAuthRequest(authRequestId);
      if (!r || r.status !== 'pending' || r.telegram_user_id !== tgUser.id || r.expires_at <= now) return null;
      const user = store.upsertTelegramUser(tgUser, now);
      const codeExpiresAt = now + config.authCodeTtl;
      if (!store.markAuthRequestApproved(r.id, tgUser.id, user.id, now, codeExpiresAt)) return null;
      store.grantConsent(user.id, r.client_id, splitScopes(r.scope), now);
      store.insertAuthorizationCode({
        code: randomToken(32),
        authRequestId: r.id,
        userId: user.id,
        clientId: r.client_id,
        redirectUri: r.redirect_uri,
        codeChallenge: r.code_challenge,
        codeChallengeMethod: r.code_challenge_method,
        scope: r.scope,
        nonce: r.nonce,
        authTime: now,
        createdAt: now,
        expiresAt: codeExpiresAt,
      });
      return { client: store.getClient(r.client_id), user };
    });
  }

  /** @param {string} authRequestId @param {TelegramUser} tgUser */
  function denyLogin(authRequestId, tgUser) {
    return store.markAuthRequestDenied(authRequestId, tgUser.id, 'access_denied', 'The user denied the request');
  }

  /** Clients the user has granted access to. @param {number} telegramUserId */
  function listGrants(telegramUserId) {
    const user = store.getUserByTelegramId(telegramUserId);
    return user ? store.listConsentedClients(user.id) : [];
  }

  /**
   * Withdraw consent: deletes the consent rows and revokes every refresh token
   * of the grant. Access tokens issued before this stop passing `/userinfo`
   * and `/introspect` immediately (they check consent), and expire on their own.
   * @param {number} telegramUserId @param {string} clientId
   */
  function revokeGrant(telegramUserId, clientId) {
    const user = store.getUserByTelegramId(telegramUserId);
    if (!user) return false;
    const now = clock.now();
    return store.transaction(() => {
      const removed = store.revokeConsent(user.id, clientId);
      store.revokeRefreshTokensForGrant(user.id, clientId, now);
      return removed > 0;
    });
  }

  // ---------------------------------------------------------------------------
  // Client authentication (client_secret_basic, client_secret_post, none)
  // ---------------------------------------------------------------------------

  /**
   * @param {{ body: Record<string, unknown>, authorization?: string }} req
   * @returns {Promise<Client>}
   */
  async function authenticateClient({ body, authorization }) {
    let clientId;
    let secret;
    if (authorization && /^basic /i.test(authorization)) {
      const decoded = Buffer.from(authorization.slice(6).trim(), 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      if (sep < 0) throw invalidClient();
      try {
        // RFC 6749 §2.3.1: both parts are form-urlencoded before base64.
        const dec = (s) => decodeURIComponent(s.replace(/\+/g, ' '));
        clientId = dec(decoded.slice(0, sep));
        secret = dec(decoded.slice(sep + 1));
      } catch {
        throw invalidClient();
      }
      if (body.client_secret !== undefined) throw invalidRequest('Use only one client authentication method');
      if (body.client_id !== undefined && body.client_id !== clientId) throw invalidRequest('client_id mismatch');
    } else {
      clientId = body.client_id;
      secret = body.client_secret;
    }
    if (typeof clientId !== 'string' || !clientId) throw invalidClient();
    if (secret !== undefined && typeof secret !== 'string') throw invalidClient();
    const presentedSecret = /** @type {string | undefined} */ (secret);

    const client = store.getClient(clientId);
    if (!client) throw invalidClient();
    if (client.secretHash) {
      if (!presentedSecret) throw invalidClient();
      const { ok, needsRehash } = await verifySecret(presentedSecret, client.secretHash);
      if (!ok) throw invalidClient();
      if (needsRehash) store.setClientSecretHash(client.clientId, await hashSecret(presentedSecret));
    } else if (presentedSecret) {
      throw invalidClient('This is a public client; it must not send a secret');
    }
    return client;
  }

  // ---------------------------------------------------------------------------
  // Token endpoint
  // ---------------------------------------------------------------------------

  function issueRefreshToken({ familyId, userId, clientId, scope, authTime, now }) {
    const token = randomToken(48);
    store.insertRefreshToken({
      tokenHash: sha256Hex(token),
      familyId,
      userId,
      clientId,
      scope,
      authTime,
      createdAt: now,
      expiresAt: now + config.refreshTokenTtl,
    });
    return token;
  }

  async function tokenResponse({ user, client, scope, nonce, authTime, refreshToken }) {
    const scopes = splitScopes(scope);
    const access = await tokens.issueAccessToken({ user, clientId: client.clientId, scope, authTime });
    /** @type {Record<string, unknown>} */
    const body = {
      access_token: access.token,
      token_type: 'Bearer',
      expires_in: access.expiresIn,
      scope,
      refresh_token: refreshToken,
    };
    if (scopes.includes('openid')) {
      body.id_token = await tokens.issueIdToken({ user, clientId: client.clientId, scopes, nonce, authTime });
    }
    return { body, access };
  }

  /**
   * authorization_code grant. The code is consumed with a single conditional
   * UPDATE, so of N concurrent exchanges exactly one wins. A replayed code
   * revokes whatever the first exchange issued (RFC 6749 §4.1.2).
   * @param {Client} client @param {Record<string, unknown>} body
   */
  async function exchangeCode(client, body) {
    const code = body.code;
    const redirectUri = body.redirect_uri;
    const verifier = body.code_verifier;
    if (typeof code !== 'string' || !code) throw invalidRequest('code is required');
    if (typeof redirectUri !== 'string' || !redirectUri) throw invalidRequest('redirect_uri is required');
    if (typeof verifier !== 'string' || !verifier) throw invalidRequest('code_verifier is required');

    const now = clock.now();
    const row = store.getAuthorizationCode(code);
    if (!row) throw invalidGrant('Invalid authorization code');
    if (!store.markCodeUsed(code, now)) {
      if (row.refresh_family_id) store.revokeRefreshFamily(row.refresh_family_id, now);
      if (row.access_token_jti) store.denylistAccessToken(row.access_token_jti, row.access_token_exp);
      logger.warn({ clientId: row.client_id, userId: row.user_id }, 'authorization code replay; issued tokens revoked');
      throw invalidGrant('Authorization code has already been used');
    }
    // From here on the code is burnt whatever the outcome.
    if (row.client_id !== client.clientId) throw invalidGrant('Code was issued to another client');
    if (row.expires_at <= now) throw invalidGrant('Authorization code expired');
    if (row.redirect_uri !== redirectUri) throw invalidGrant('redirect_uri does not match the authorization request');
    if (!PKCE_VERIFIER.test(verifier)) throw invalidGrant('Malformed code_verifier');
    if (!safeEqual(sha256Base64url(verifier), row.code_challenge)) throw invalidGrant('PKCE verification failed');

    const user = store.getUser(row.user_id);
    if (!user) throw invalidGrant('User no longer exists');
    const familyId = randomToken(16);
    const refreshToken = issueRefreshToken({
      familyId, userId: user.id, clientId: client.clientId, scope: row.scope, authTime: row.auth_time, now,
    });
    const { body: response, access } = await tokenResponse({
      user, client, scope: row.scope, nonce: row.nonce, authTime: row.auth_time, refreshToken,
    });
    store.setCodeIssuedTokens(code, familyId, access.jti, access.exp);
    return response;
  }

  /**
   * refresh_token grant with rotation and reuse detection. Rotation is one
   * conditional UPDATE; presenting an already-rotated token is treated as a
   * leak and revokes every refresh token of that user/client grant.
   * @param {Client} client @param {Record<string, unknown>} body
   */
  async function refresh(client, body) {
    const presented = body.refresh_token;
    if (typeof presented !== 'string' || !presented) throw invalidRequest('refresh_token is required');
    const hash = sha256Hex(presented);
    const now = clock.now();

    const outcome = store.transaction(() => {
      if (store.markRefreshTokenRotated(hash, client.clientId, now)) {
        const row = store.getRefreshTokenByHash(hash);
        const next = issueRefreshToken({
          familyId: row.family_id, userId: row.user_id, clientId: row.client_id,
          scope: row.scope, authTime: row.auth_time, now,
        });
        return { row, next };
      }
      const row = store.getRefreshTokenByHash(hash);
      if (row && row.client_id === client.clientId && row.rotated_at !== null && row.revoked_at === null) {
        const revoked = store.revokeRefreshTokensForGrant(row.user_id, row.client_id, now);
        return { reuse: { userId: row.user_id, revoked } };
      }
      return {};
    });

    if (outcome.reuse) {
      logger.warn({ clientId: client.clientId, ...outcome.reuse }, 'refresh token reuse detected; grant revoked');
      throw invalidGrant('Refresh token has already been used');
    }
    if (!outcome.row) throw invalidGrant('Invalid refresh token');
    const { row, next } = outcome;

    const granted = splitScopes(row.scope);
    let scope = row.scope;
    if (body.scope !== undefined) {
      const requested = splitScopes(/** @type {string} */ (body.scope));
      const extra = requested.filter((s) => !granted.includes(s));
      if (extra.length) throw new OAuthError('invalid_scope', `Scope exceeds the original grant: ${extra.join(' ')}`);
      scope = requested.join(' ');
    }

    const user = store.getUser(row.user_id);
    if (!user) throw invalidGrant('User no longer exists');
    if (config.reevaluatePolicyOnRefresh && client.policy) {
      const result = await evaluatePolicy(client.policy, subjectFromUser(user), ctx.telegram);
      if (!result.pass) {
        store.revokeRefreshTokensForGrant(user.id, client.clientId, now);
        throw invalidGrant('The user no longer satisfies this application\'s access policy');
      }
    }
    const { body: response } = await tokenResponse({
      user, client, scope, nonce: null, authTime: row.auth_time, refreshToken: next,
    });
    return response;
  }

  /**
   * @param {Record<string, unknown>} body
   * @param {string | undefined} authorization
   */
  async function token(body, authorization) {
    const grantType = body.grant_type;
    if (typeof grantType !== 'string' || !grantType) throw invalidRequest('grant_type is required');
    if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
      throw new OAuthError('unsupported_grant_type', `Unsupported grant_type: ${grantType}`);
    }
    const client = await authenticateClient({ body, authorization });
    return grantType === 'authorization_code' ? exchangeCode(client, body) : refresh(client, body);
  }

  // ---------------------------------------------------------------------------
  // Access token state: userinfo, introspection, revocation
  // ---------------------------------------------------------------------------

  /**
   * Beyond the signature: not revoked, user and client still exist, consent
   * still granted and not re-granted after the token was issued, and
   * (optionally) the client's policy still holds right now.
   */
  async function accessTokenState(payload, { checkPolicy }) {
    if (store.isAccessTokenDenylisted(payload.jti)) return null;
    const user = store.getUser(payload.sub);
    const client = store.getClient(payload.client_id);
    if (!user || !client) return null;
    const consents = store.getConsents(user.id, client.clientId);
    if (consents.length === 0 || consents.some((c) => c.granted_at > payload.iat)) return null;
    if (checkPolicy && client.policy) {
      const result = await evaluatePolicy(client.policy, subjectFromUser(user), ctx.telegram);
      if (!result.pass) return null;
    }
    return { user, client };
  }

  /** @param {string} accessToken */
  async function userinfo(accessToken) {
    const payload = await tokens.verifyAccessToken(accessToken);
    const state = await accessTokenState(payload, { checkPolicy: false });
    if (!state) throw invalidToken();
    const scopes = splitScopes(/** @type {string} */ (payload.scope));
    if (!scopes.includes('openid')) throw new OAuthError('insufficient_scope', 'The openid scope is required', 403);
    return { sub: String(state.user.id), ...profileClaims(state.user, scopes) };
  }

  /**
   * RFC 7662. A client may only introspect its own tokens. For access tokens
   * the client's policy is re-evaluated live, so a resource server that
   * introspects gets per-request enforcement (e.g. group removal).
   * @param {Client} client @param {Record<string, unknown>} body
   */
  async function introspect(client, body) {
    const presented = body.token;
    if (typeof presented !== 'string' || !presented) throw invalidRequest('token is required');
    const now = clock.now();
    const inactive = { active: false };

    const rt = store.getRefreshTokenByHash(sha256Hex(presented));
    if (rt) {
      const consents = store.getConsents(rt.user_id, rt.client_id);
      const active = rt.client_id === client.clientId && rt.revoked_at === null && rt.rotated_at === null
        && rt.expires_at > now && consents.length > 0;
      if (!active) return inactive;
      return {
        active: true, token_type: 'refresh_token', client_id: rt.client_id, sub: String(rt.user_id),
        scope: rt.scope, iat: rt.created_at, exp: rt.expires_at, iss: config.issuer,
      };
    }

    let payload;
    try {
      payload = await tokens.verifyAccessToken(presented);
    } catch {
      return inactive;
    }
    if (payload.client_id !== client.clientId) return inactive;
    const state = await accessTokenState(payload, { checkPolicy: true });
    if (!state) return inactive;
    return {
      active: true,
      token_type: 'Bearer',
      client_id: payload.client_id,
      sub: payload.sub,
      scope: payload.scope,
      iat: payload.iat,
      exp: payload.exp,
      jti: payload.jti,
      iss: payload.iss,
      aud: payload.aud,
      username: state.user.telegram_username ?? undefined,
      telegram_id: state.user.telegram_user_id,
    };
  }

  /**
   * RFC 7009. Refresh tokens revoke their whole rotation family; access
   * tokens are added to the jti denylist. Unknown tokens are not an error.
   * @param {Client} client @param {Record<string, unknown>} body
   */
  async function revoke(client, body) {
    const presented = body.token;
    if (typeof presented !== 'string' || !presented) throw invalidRequest('token is required');
    const now = clock.now();
    const rt = store.getRefreshTokenByHash(sha256Hex(presented));
    if (rt) {
      if (rt.client_id === client.clientId) store.revokeRefreshFamily(rt.family_id, now);
      return;
    }
    try {
      const payload = await tokens.verifyAccessToken(presented);
      if (payload.client_id === client.clientId) store.denylistAccessToken(payload.jti, payload.exp);
    } catch {
      // Invalid or foreign tokens are silently ignored (RFC 7009 §2.2).
    }
  }

  return {
    authorize,
    getAuthRequestStatus,
    beginTelegramLogin,
    approveLogin,
    denyLogin,
    listGrants,
    revokeGrant,
    authenticateClient,
    token,
    userinfo,
    introspect,
    revoke,
  };
}
