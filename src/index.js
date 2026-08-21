import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import path from 'path';
import crypto from 'crypto';
import { jwtVerify } from 'jose';
import { config } from './config.js';
import defaultDb, { createDatabase } from './db.js';
import { bot as defaultBot } from './bot.js';
import {
  setDb,
  createAuthRequest,
  getAuthRequestById,
  createAuthorizationCode,
  consumeAuthorizationCode,
  createRefreshToken,
  rotateRefreshToken,
  validateRefreshToken,
  revokeRefreshToken,
} from './oauth.js';
import { createAccessToken, createIdToken, getJwks, getKeyPair } from './tokens.js';
import { generateQrDataUrl } from './qr.js';

export async function buildApp(options = {}) {
  const app = Fastify({ logger: options.logger ?? false });
  const db = options.db || defaultDb;
  setDb(db);
  const baseUrl = options.baseUrl || config.baseUrl;
  const telegramBotToken = options.telegramBotToken || config.telegramBotToken;
  const telegramWebhookSecret = options.telegramWebhookSecret || config.telegramWebhookSecret;
  const keysDir = options.keysDir || config.keysDir;
  const accessTokenTtl = options.accessTokenTtl || config.accessTokenTtl;
  const refreshTokenTtl = options.refreshTokenTtl || config.refreshTokenTtl;
  const authRequestTtl = options.authRequestTtl || config.authRequestTtl;
  const bot = options.bot || defaultBot;

  // Override config for JWT functions (they use global config, so we need to set)
  // We'll temporarily set config fields; this is okay for single process.
  // For tests we pass a custom config object to token functions? We'll just rely on config global for now,
  // but we set them here so any function using config gets the right values.
  config.baseUrl = baseUrl;
  config.keysDir = keysDir;
  config.accessTokenTtl = accessTokenTtl;
  config.refreshTokenTtl = refreshTokenTtl;
  config.authRequestTtl = authRequestTtl;
  config.telegramBotToken = telegramBotToken;
  config.telegramWebhookSecret = telegramWebhookSecret;

  app.register(fastifyCookie);
  app.register(fastifyStatic, { root: path.join(process.cwd(), 'public') });

  // OIDC Discovery
  app.get('/.well-known/openid-configuration', async () => ({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    userinfo_endpoint: `${baseUrl}/userinfo`,
    jwks_uri: `${baseUrl}/jwks`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
  }));

  app.get('/jwks', async () => getJwks());

  // Authorize endpoint
  app.get('/authorize', async (req, reply) => {
    const { client_id, redirect_uri, response_type, state, scope, nonce, code_challenge, code_challenge_method } = req.query;
    if (response_type !== 'code') return reply.code(400).send('unsupported response_type');
    if (!code_challenge || code_challenge_method !== 'S256') return reply.code(400).send('PKCE required');

    const client = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(client_id);
    if (!client) return reply.code(401).send('invalid client');
    const redirectUris = JSON.parse(client.redirect_uris);
    if (!redirectUris.includes(redirect_uri)) return reply.code(400).send('invalid redirect_uri');

    let browserSessionId = req.cookies.browser_session_id;
    if (!browserSessionId) {
      browserSessionId = crypto.randomBytes(16).toString('hex');
      reply.setCookie('browser_session_id', browserSessionId, { httpOnly: true, sameSite: 'lax', path: '/' });
    }

    const { id, token } = createAuthRequest({
      clientId: client_id,
      redirectUri: redirect_uri,
      state,
      scope: scope || 'openid profile telegram',
      nonce,
      codeChallenge: code_challenge,
      codeChallengeMethod: code_challenge_method,
      browserSessionId,
      ttl: authRequestTtl * 1000,
    });

    const deepLink = `https://t.me/${bot.botInfo.username}?start=auth_${token}`;
    const qrDataUrl = await generateQrDataUrl(deepLink);

    const html = `<!DOCTYPE html>
<html>
<head><title>Sign in with Telegram</title>
<style>body{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;height:100vh;margin:0} img{width:300px;height:300px} .status{margin-top:20px;font-size:18px}</style>
</head>
<body>
<h1>Scan with Telegram</h1>
<img src="${qrDataUrl}" alt="QR Code" />
<p class="status" id="status">Waiting for approval...</p>
<script>
const poll = async () => {
  try {
    const res = await fetch('/auth-request/${id}/status');
    if (!res.ok) return;
    const data = await res.json();
    if (data.status === 'approved') {
      document.getElementById('status').textContent = 'Approved! Redirecting...';
      const url = new URL(data.redirect_uri);
      url.searchParams.set('code', data.code);
      url.searchParams.set('state', data.state);
      window.location.href = url.toString();
    } else if (data.status === 'denied') {
      document.getElementById('status').textContent = 'Denied. ' + (data.reason || '');
    }
  } catch(e) {}
};
setInterval(poll, 2000);
</script>
</body>
</html>`;
    reply.type('text/html').send(html);
  });

  // Poll status endpoint
  app.get('/auth-request/:id/status', async (req, reply) => {
    const { id } = req.params;
    const browserSessionId = req.cookies.browser_session_id;
    const authRequest = getAuthRequestById(id);
    if (!authRequest || authRequest.browser_session_id !== browserSessionId) {
      return reply.code(404).send({ status: 'invalid' });
    }
    if (authRequest.status === 'approved') {
      const codeRow = db.prepare('SELECT code FROM authorization_codes WHERE auth_request_id = ? AND used = 0').get(id);
      if (codeRow) {
        return { status: 'approved', redirect_uri: authRequest.redirect_uri, state: authRequest.state, code: codeRow.code };
      }
    }
    return { status: authRequest.status, reason: authRequest.reason || undefined };
  });

  // Token endpoint
  app.post('/token', async (req, reply) => {
    const { grant_type } = req.body;
    if (!grant_type) return reply.code(400).send({ error: 'invalid_request' });

    if (grant_type === 'authorization_code') {
      const { code, redirect_uri, client_id, code_verifier } = req.body;

      // Check client and secret
      const client = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(client_id);
      if (!client) return reply.code(401).send({ error: 'invalid_client' });
      if (client.client_secret_hash) {
        const { client_secret } = req.body;
        if (!client_secret) return reply.code(401).send({ error: 'invalid_client' });
        const providedHash = crypto.createHash('sha256').update(client_secret).digest();
        const expectedBuffer = Buffer.from(client.client_secret_hash, 'hex');
        if (providedHash.length !== expectedBuffer.length || !crypto.timingSafeEqual(providedHash, expectedBuffer)) {
          return reply.code(401).send({ error: 'invalid_client' });
        }
      }

      const data = consumeAuthorizationCode(code, redirect_uri, client_id, code_verifier);
      if (!data) return reply.code(400).send({ error: 'invalid_grant' });

      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(data.userId);
      if (!user) return reply.code(400).send({ error: 'invalid_grant' });

      const accessToken = await createAccessToken(user, client_id, data.scope);
      const idToken = await createIdToken(user, client_id, data.nonce);

      // Issue refresh token if scope includes offline_access (or always; we'll always issue for now)
      const refreshToken = createRefreshToken(user.id, client_id, data.scope);

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: Math.floor(parseDurationToSeconds(config.accessTokenTtl)),
        id_token: idToken,
        refresh_token: refreshToken,
      };
    }

    if (grant_type === 'refresh_token') {
      const { refresh_token, client_id, client_secret } = req.body;

      // Validate client
      const client = db.prepare('SELECT * FROM oauth_clients WHERE client_id = ?').get(client_id);
      if (!client) return reply.code(401).send({ error: 'invalid_client' });
      if (client.client_secret_hash) {
        if (!client_secret) return reply.code(401).send({ error: 'invalid_client' });
        const providedHash = crypto.createHash('sha256').update(client_secret).digest();
        const expectedBuffer = Buffer.from(client.client_secret_hash, 'hex');
        if (providedHash.length !== expectedBuffer.length || !crypto.timingSafeEqual(providedHash, expectedBuffer)) {
          return reply.code(401).send({ error: 'invalid_client' });
        }
      }

      const tokenData = validateRefreshToken(refresh_token, client_id);
      if (!tokenData) return reply.code(400).send({ error: 'invalid_grant' });

      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(tokenData.user_id);
      if (!user) return reply.code(400).send({ error: 'invalid_grant' });

      const accessToken = await createAccessToken(user, client_id, tokenData.scope);
      // Rotate refresh token
      const newRefreshToken = rotateRefreshToken(refresh_token, user.id, client_id, tokenData.scope);

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: Math.floor(parseDurationToSeconds(config.accessTokenTtl)),
        refresh_token: newRefreshToken,
      };
    }

    return reply.code(400).send({ error: 'unsupported_grant_type' });
  });

  // Userinfo endpoint
  app.get('/userinfo', async (req, reply) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) return reply.code(401).send({ error: 'missing_token' });
    const token = authHeader.slice(7);
    try {
      const { publicKey } = await getKeyPair();
      const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
        issuer: baseUrl,
      });
      if (protectedHeader.typ !== 'at+jwt') throw new Error('invalid token type');
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
      if (!user) return reply.code(404).send({ error: 'user_not_found' });
      return {
        sub: user.id.toString(),
        telegram_id: user.telegram_user_id,
        preferred_username: user.telegram_username,
        name: [user.first_name, user.last_name].filter(Boolean).join(' '),
        picture: user.photo_url,
      };
    } catch {
      return reply.code(401).send({ error: 'invalid_token' });
    }
  });

  // Telegram webhook endpoint (only used in production)
  app.post('/telegram-webhook', async (req, reply) => {
    const secret = req.headers['x-telegram-bot-api-secret-token'];
    if (secret !== telegramWebhookSecret) return reply.code(403).send({ ok: false });
    try {
      await bot.handleUpdate(req.body);
      reply.send({ ok: true });
    } catch (err) {
      req.log.error(err);
      reply.code(500).send({ ok: false });
    }
  });

  // Periodic cleanup
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    db.prepare('DELETE FROM authorization_codes WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM auth_requests WHERE expires_at < ?').run(now);
    db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked_at IS NOT NULL').run(now);
  }, 60_000);
  cleanupInterval.unref();

  return app;
}

function parseDurationToSeconds(duration) {
  const match = duration.match(/^(\d+)([smhd])$/);
  if (!match) return 900;
  const value = parseInt(match[1], 10);
  const unit = match[2];
  const factors = { s: 1, m: 60, h: 3600, d: 86400 };
  return value * (factors[unit] || 60);
}

export async function start() {
  const app = await buildApp({ logger: true });
  await defaultBot.init();
  const webhookUrl = `${config.baseUrl}/telegram-webhook`;
  await defaultBot.api.setWebhook(webhookUrl, { secret_token: config.telegramWebhookSecret });
  app.log.info(`Webhook set to ${webhookUrl}`);
  await app.listen({ port: config.port, host: '0.0.0.0' });
}

// Run only if this file is executed directly (not imported)
if (process.argv[1] === import.meta.url) {
  start().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
