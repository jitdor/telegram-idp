import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import { randomToken } from './util.js';
import { invalidToken } from './errors.js';

/** @typedef {import('./types.js').User} User */
/** @typedef {import('./types.js').KeyStore} KeyStore */
/** @typedef {ReturnType<typeof createTokenService>} TokenService */

/**
 * Claims derived from the user profile, filtered by granted scope.
 * @param {User} user
 * @param {string[]} scopes
 */
export function profileClaims(user, scopes) {
  /** @type {Record<string, unknown>} */
  const claims = {};
  if (scopes.includes('profile')) {
    const name = [user.first_name, user.last_name].filter(Boolean).join(' ');
    if (name) claims.name = name;
    if (user.first_name) claims.given_name = user.first_name;
    if (user.last_name) claims.family_name = user.last_name;
    if (user.telegram_username) claims.preferred_username = user.telegram_username;
    if (user.photo_url) claims.picture = user.photo_url;
    if (user.language_code) claims.locale = user.language_code;
  }
  if (scopes.includes('telegram')) {
    claims.telegram_id = user.telegram_user_id;
    claims.telegram_is_premium = user.is_premium === 1;
  }
  return claims;
}

/**
 * JWT issuance and verification, bound to one issuer and key store.
 * @param {{ config: import('./types.js').IdpConfig, keys: KeyStore, clock: import('./types.js').Clock }} deps
 */
export function createTokenService({ config, keys, clock }) {
  const issuer = config.issuer;
  /** Audience the IdP's own resource (userinfo, introspection) requires. */
  const resourceAudience = `${issuer}/userinfo`;

  async function sign(claims, typ, ttl) {
    const { kid, alg, privateKey } = await keys.getSigningKey();
    const iat = clock.now();
    const jwt = new SignJWT(claims)
      .setProtectedHeader({ alg, kid, ...(typ ? { typ } : {}) })
      .setIssuer(issuer)
      .setIssuedAt(iat)
      .setExpirationTime(iat + ttl);
    return { jwt: await jwt.sign(privateKey), iat, exp: iat + ttl };
  }

  return {
    resourceAudience,

    /**
     * RFC 9068 access token. The audience names both the IdP resource (so
     * `/userinfo` can require it) and the client (for backwards compatibility).
     * @param {{ user: User, clientId: string, scope: string, authTime?: number | null }} p
     */
    async issueAccessToken({ user, clientId, scope, authTime }) {
      const jti = randomToken(16);
      const { jwt, exp } = await sign({
        sub: String(user.id),
        aud: [resourceAudience, clientId],
        client_id: clientId,
        scope,
        jti,
        ...(authTime ? { auth_time: authTime } : {}),
      }, 'at+jwt', config.accessTokenTtl);
      return { token: jwt, jti, exp, expiresIn: config.accessTokenTtl };
    },

    /**
     * @param {{ user: User, clientId: string, scopes: string[], nonce?: string | null, authTime?: number | null }} p
     */
    async issueIdToken({ user, clientId, scopes, nonce, authTime }) {
      const { jwt } = await sign({
        sub: String(user.id),
        aud: clientId,
        azp: clientId,
        ...(nonce ? { nonce } : {}),
        ...(authTime ? { auth_time: authTime } : {}),
        ...profileClaims(user, scopes),
      }, null, config.idTokenTtl);
      return jwt;
    },

    /**
     * Verify an access token minted by this IdP: signature (by `kid`), RS256
     * only, `typ: at+jwt`, issuer, audience and expiry.
     * @param {string} token
     */
    async verifyAccessToken(token) {
      try {
        const { payload } = await jwtVerify(token, async (header) => {
          const key = await keys.getVerificationKey(header.kid);
          if (!key) throw new joseErrors.JWKSNoMatchingKey();
          return key;
        }, {
          issuer,
          audience: resourceAudience,
          typ: 'at+jwt',
          algorithms: ['RS256'],
          currentDate: new Date(clock.now() * 1000),
          requiredClaims: ['sub', 'client_id', 'jti', 'exp', 'iat'],
        });
        return payload;
      } catch {
        throw invalidToken();
      }
    },

    getJwks: () => keys.getJwks(),
  };
}
