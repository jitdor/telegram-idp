import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifyStatic from '@fastify/static';
import path from 'path';
import crypto from 'crypto';
import { jwtVerify } from 'jose';
import { config } from './config.js';
import db from './db.js';
import { bot } from './bot.js';
import {
  createAuthRequest,
  getAuthRequestById,
  createAuthorizationCode,
  consumeAuthorizationCode,
} from './oauth.js';
import { createAccessToken, createIdToken, getJwks, getKeyPair } from './tokens.js';
import { generateQrDataUrl } from './qr.js';

const app = Fastify({ logger: true });

app.register(fastifyCookie);
app.register(fastifyStatic, { root: path.join(process.cwd(), 'public') });

// OIDC Discovery
app.get('/.well-known/openid-configuration', async () => ({
  issuer: config.baseUrl,
  authorization_endpoint: `${config.baseUrl}/authorize`,
  token_endpoint: `${config.baseUrl}/token`,
  userinfo_endpoint: `${config.baseUrl}/userinfo`,
  jwks_uri: `${config.baseUrl}/jwks`,
  response_types_supported: ['code'],
  grant_types_supported: ['authorization_code'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['RS256'],
  token_endpoint_auth_methods_supported: ['none'],
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
    // Fetch the (single) authorization code from DB
    const codeRow = db.prepare('SELECT code FROM authorization_codes WHERE auth_request_id = ? AND used = 0').get(id);
    if (codeRow) {
      return { status: 'approved', redirect_uri: authRequest.redirect_uri, state: authRequest.state, code: codeRow.code };
    }
  }
  return { status: authRequest.status, reason: authRequest.reason || undefined };
});

// Token endpoint
app.post('/token', async (req, reply) => {
  const { grant_type, code, redirect_uri, client_id, code_verifier } = req.body;
  if (grant_type !== 'authorization_code') return reply.code(400).send({ error: 'unsupported_grant_type' });

  // Check client and secret (constant-time, no enumeration)
  const client = db.prepare('SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?').get(client_id);
  if (!client) return reply.code(401).send({ error: 'invalid_client' });
  const expectedHash = client.client_secret_hash;
  if (expectedHash) {
    const { client_secret } = req.body;
    if (!client_secret) return reply.code(401).send({ error: 'invalid_client' });
    const providedHash = crypto.createHash('sha256').update(client_secret).digest();
    const expectedBuffer = Buffer.from(expectedHash, 'hex');
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

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    id_token: idToken,
  };
});

// Userinfo endpoint
app.get('/userinfo', async (req, reply) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return reply.code(401).send({ error: 'missing_token' });
  const token = authHeader.slice(7);
  try {
    const { publicKey } = await getKeyPair();
    const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
      issuer: config.baseUrl,
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

// Telegram webhook endpoint
app.post('/telegram-webhook', async (req, reply) => {
  const secret = req.headers['x-telegram-bot-api-secret-token'];
  if (secret !== config.telegramWebhookSecret) return reply.code(403).send({ ok: false });
  try {
    await bot.handleUpdate(req.body);
    reply.send({ ok: true });
  } catch (err) {
    req.log.error(err);
    reply.code(500).send({ ok: false });
  }
});

// Start server and set webhook
const start = async () => {
  await bot.init();
  const webhookUrl = `${config.baseUrl}/telegram-webhook`;
  await bot.api.setWebhook(webhookUrl, { secret_token: config.telegramWebhookSecret });
  app.log.info(`Webhook set to ${webhookUrl}`);
  await app.listen({ port: config.port, host: '0.0.0.0' });

  // Periodic cleanup of expired/used codes and auth_requests
  setInterval(() => {
    const now = Date.now();
    db.prepare('DELETE FROM authorization_codes WHERE expires_at < ? OR used = 1').run(now);
    db.prepare('DELETE FROM auth_requests WHERE expires_at < ? OR status IN (?, ?)').run(now, 'denied', 'approved');
  }, 60_000).unref();
};

start().catch((err) => {
  console.error(err);
  process.exit(1);
});
