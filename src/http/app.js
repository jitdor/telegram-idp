import { readFileSync } from 'node:fs';
import crypto from 'node:crypto';
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import { SUPPORTED_SCOPES } from '../config.js';
import { OAuthError, UnsafeRedirectError, invalidRequest } from '../errors.js';
import { generateQrDataUrl } from '../qr.js';
import { createRateLimiter } from '../rate-limit.js';
import { safeEqual } from '../util.js';
import { errorPage, loginPage } from './pages.js';

/** @typedef {import('../types.js').IdpContext} IdpContext */

const STATIC = {
  'login.js': {
    type: 'text/javascript; charset=utf-8',
    body: readFileSync(new URL('../../public/login.js', import.meta.url), 'utf8'),
  },
  'login.css': {
    type: 'text/css; charset=utf-8',
    body: readFileSync(new URL('../../public/login.css', import.meta.url), 'utf8'),
  },
};

const PAGE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  'img-src data:',
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

const NO_STORE = { 'cache-control': 'no-store', pragma: 'no-cache' };

/**
 * HTTP adapter: maps Fastify requests onto the context's OAuth service.
 * @param {IdpContext} ctx
 * @param {object} [options]
 * @param {boolean | object} [options.logger] Fastify logger option
 * @param {{ handleUpdate: (update: any) => Promise<unknown> } | null} [options.bot] receives webhook updates
 * @param {import('../rate-limit.js').RateLimiter} [options.rateLimiter]
 * @param {number} [options.maintenanceIntervalMs] expired-row sweep period; 0 disables
 */
export async function buildApp(ctx, options = {}) {
  const { config, oauth } = ctx;
  const app = Fastify({ logger: options.logger ?? false, trustProxy: config.trustProxy });
  const limiter = options.rateLimiter ?? createRateLimiter({ clock: ctx.clock });
  const secureCookies = config.issuer.startsWith('https://');
  // __Host- cookies are pinned to this exact origin (Secure, Path=/, no Domain).
  const sessionCookie = secureCookies ? '__Host-tgidp_session' : 'tgidp_session';

  await app.register(fastifyCookie);

  // RFC 6749 requires application/x-www-form-urlencoded at the token endpoint.
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (req, body, done) => {
    const params = new URLSearchParams(/** @type {string} */ (body));
    /** @type {Record<string, string>} */
    const out = {};
    for (const key of new Set(params.keys())) {
      const values = params.getAll(key);
      if (values.length > 1) return done(invalidRequest(`${key} must be provided once`), undefined);
      out[key] = values[0];
    }
    done(null, out);
  });

  app.setErrorHandler((err, req, reply) => {
    if (err instanceof OAuthError) {
      if (err.status === 401 && err.error === 'invalid_client' && /^basic /i.test(req.headers.authorization || '')) {
        reply.header('www-authenticate', 'Basic realm="telegram-idp"');
      }
      return reply.code(err.status).headers(NO_STORE).send(err.toJSON());
    }
    const status = /** @type {any} */ (err).statusCode;
    if (status && status >= 400 && status < 500) {
      return reply.code(status).send({ error: 'invalid_request', error_description: /** @type {Error} */ (err).message });
    }
    req.log.error(err);
    return reply.code(500).send({ error: 'server_error' });
  });

  app.setNotFoundHandler((req, reply) => reply.code(404).send({ error: 'not_found' }));

  /** preHandler that applies a per-IP limit from config.rateLimits */
  const limit = (name) => async (req, reply) => {
    const { allowed, retryAfter } = limiter.hit(`${name}:${req.ip}`, config.rateLimits[name]);
    if (!allowed) {
      reply.code(429).header('retry-after', String(retryAfter))
        .send({ error: 'temporarily_unavailable', error_description: 'Too many requests' });
      return reply;
    }
  };

  const bodyOf = (req) => (req.body && typeof req.body === 'object' ? req.body : {});

  // ---- discovery ----

  app.get('/.well-known/openid-configuration', async (req, reply) => {
    reply.header('cache-control', 'public, max-age=300');
    const iss = config.issuer;
    return {
      issuer: iss,
      authorization_endpoint: `${iss}/authorize`,
      token_endpoint: `${iss}/token`,
      userinfo_endpoint: `${iss}/userinfo`,
      jwks_uri: `${iss}/jwks`,
      revocation_endpoint: `${iss}/revoke`,
      introspection_endpoint: `${iss}/introspect`,
      scopes_supported: SUPPORTED_SCOPES,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      revocation_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      introspection_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'azp', 'name', 'given_name',
        'family_name', 'preferred_username', 'picture', 'locale', 'telegram_id', 'telegram_is_premium'],
      authorization_response_iss_parameter_supported: true,
    };
  });

  app.get('/jwks', async (req, reply) => {
    reply.header('cache-control', 'public, max-age=300');
    return ctx.tokens.getJwks();
  });

  app.get('/static/:file', async (req, reply) => {
    const file = STATIC[/** @type {any} */ (req.params).file];
    if (!file) return reply.callNotFound();
    return reply.type(file.type).header('cache-control', 'public, max-age=3600')
      .header('x-content-type-options', 'nosniff').send(file.body);
  });

  // ---- authorization ----

  const sendPage = (reply, status, html) => reply.code(status).headers({
    ...NO_STORE,
    'content-security-policy': PAGE_CSP,
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
  }).type('text/html; charset=utf-8').send(html);

  app.get('/authorize', { preHandler: limit('authorize') }, async (req, reply) => {
    let browserSessionId = req.cookies[sessionCookie];
    if (!browserSessionId || !/^[0-9a-f]{32}$/.test(browserSessionId)) {
      browserSessionId = crypto.randomBytes(16).toString('hex');
      reply.setCookie(sessionCookie, browserSessionId, {
        httpOnly: true, sameSite: 'lax', path: '/', secure: secureCookies,
      });
    }
    let result;
    try {
      result = await oauth.authorize(/** @type {Record<string, unknown>} */ (req.query), browserSessionId);
    } catch (err) {
      if (!(err instanceof UnsafeRedirectError)) throw err;
      // Never redirect to an unverified URI: show the error here instead.
      return sendPage(reply, 400, errorPage({ title: 'Sign-in error', message: err.description || err.error }));
    }
    if (result.kind === 'redirect') return reply.headers(NO_STORE).redirect(result.location, 302);
    const qrDataUrl = await generateQrDataUrl(result.deepLink);
    return sendPage(reply, 200, loginPage({
      clientName: result.client.name,
      qrDataUrl,
      deepLink: result.deepLink,
      statusUrl: `/auth-request/${encodeURIComponent(result.authRequestId)}/status`,
    }));
  });

  app.get('/auth-request/:id/status', { preHandler: limit('status') }, async (req, reply) => {
    const status = oauth.getAuthRequestStatus(/** @type {any} */ (req.params).id, req.cookies[sessionCookie]);
    reply.headers(NO_STORE);
    if (!status) return reply.code(404).send({ error: 'not_found' });
    return status;
  });

  // ---- token, userinfo, introspection, revocation ----

  app.post('/token', { preHandler: limit('token') }, async (req, reply) => {
    const body = await oauth.token(bodyOf(req), req.headers.authorization);
    return reply.headers(NO_STORE).send(body);
  });

  const userinfo = async (req, reply) => {
    const header = req.headers.authorization || '';
    const m = /^Bearer\s+(\S+)$/i.exec(header);
    reply.headers(NO_STORE);
    if (!m) {
      return reply.code(401).header('www-authenticate', 'Bearer realm="telegram-idp"')
        .send({ error: 'invalid_request', error_description: 'Bearer token required' });
    }
    try {
      return await oauth.userinfo(m[1]);
    } catch (err) {
      if (err instanceof OAuthError) {
        reply.header('www-authenticate', `Bearer realm="telegram-idp", error="${err.error}"`);
      }
      throw err;
    }
  };
  app.get('/userinfo', { preHandler: limit('userinfo') }, userinfo);
  app.post('/userinfo', { preHandler: limit('userinfo') }, userinfo);

  app.post('/introspect', { preHandler: limit('introspect') }, async (req, reply) => {
    const body = bodyOf(req);
    const client = await oauth.authenticateClient({ body, authorization: req.headers.authorization });
    return reply.headers(NO_STORE).send(await oauth.introspect(client, body));
  });

  app.post('/revoke', { preHandler: limit('revoke') }, async (req, reply) => {
    const body = bodyOf(req);
    const client = await oauth.authenticateClient({ body, authorization: req.headers.authorization });
    await oauth.revoke(client, body);
    return reply.headers(NO_STORE).code(200).send({});
  });

  // ---- Telegram webhook ----

  const bot = options.bot;
  if (bot && config.telegramWebhookSecret) {
    const expected = config.telegramWebhookSecret;
    app.post('/telegram-webhook', async (req, reply) => {
      const secret = req.headers['x-telegram-bot-api-secret-token'];
      if (typeof secret !== 'string' || !safeEqual(secret, expected)) return reply.code(403).send({ ok: false });
      try {
        await bot.handleUpdate(req.body);
        return { ok: true };
      } catch (err) {
        req.log.error(err);
        return reply.code(500).send({ ok: false });
      }
    });
  }

  // ---- housekeeping ----

  const intervalMs = options.maintenanceIntervalMs ?? 60_000;
  if (intervalMs > 0) {
    const timer = setInterval(() => {
      try {
        ctx.store.deleteExpired(ctx.clock.now());
      } catch (err) {
        app.log.error(err, 'cleanup failed');
      }
    }, intervalMs);
    timer.unref();
    app.addHook('onClose', async () => clearInterval(timer));
  }

  return app;
}
