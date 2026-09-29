import crypto from 'node:crypto';
import { buildApp } from '../src/http/app.js';
import { defineConfig } from '../src/config.js';
import { createIdpContext } from '../src/context.js';
import { createDatabase } from '../src/db.js';
import { createMemoryKeyStore } from '../src/keys.js';
import { registerClient } from '../src/clients.js';

export const REDIRECT_URI = 'https://client.example.com/callback';

let sharedKeys;
/** RSA generation is slow; tests share one key set unless they need their own. */
export async function testKeys() {
  sharedKeys ??= await createMemoryKeyStore();
  return sharedKeys;
}

export function createTestClock(start = 1_750_000_000) {
  let t = start;
  return { now: () => t, advance: (s) => { t += s; } };
}

/**
 * Fake Telegram API. `members` maps "chatId:userId" to a chat member status.
 * @param {Record<string, string>} members
 */
export function fakeTelegram(members = {}) {
  return {
    members,
    async getChatMember(chatId, userId) {
      const status = members[`${chatId}:${userId}`];
      if (!status) throw new Error('Bad Request: user not found');
      return { status };
    },
  };
}

export function tgUser(overrides = {}) {
  return { id: 1001, username: 'alice', first_name: 'Alice', last_name: 'Liddell', language_code: 'en', ...overrides };
}

/** A fully isolated IdP instance: own DB, clock, config; nothing global. */
export async function createTestIdp(options = {}) {
  const clock = options.clock ?? createTestClock();
  const db = options.db ?? createDatabase(':memory:');
  const config = defineConfig({ issuer: 'https://idp.test', telegramBotUsername: 'test_bot', ...options.config });
  const telegram = options.telegram ?? fakeTelegram();
  const ctx = createIdpContext({
    config, db, clock, telegram, keys: options.keys ?? await testKeys(), logger: options.logger,
  });
  const app = await buildApp(ctx, { maintenanceIntervalMs: 0, bot: options.bot });
  return { ctx, app, db, clock, config, telegram };
}

export async function addClient(ctx, overrides = {}) {
  return registerClient(ctx.store, {
    clientId: 'test-client',
    name: 'Test Client',
    redirectUris: [REDIRECT_URI],
    scopes: 'openid profile telegram offline_access',
    ...overrides,
  }, ctx.clock.now());
}

export function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export function authorizeUrl(params) {
  const q = new URLSearchParams({
    client_id: 'test-client',
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    code_challenge_method: 'S256',
    ...params,
  });
  return `/authorize?${q}`;
}

/** Start a login in the "browser"; returns the deep-link token and the session cookie. */
export async function startLogin(app, params = {}) {
  const res = await app.inject({ url: authorizeUrl(params) });
  if (res.statusCode !== 200) throw new Error(`authorize failed: ${res.statusCode} ${res.headers.location || res.body}`);
  const token = /start=auth_([A-Za-z0-9_-]+)/.exec(res.body)[1];
  const statusUrl = /data-status-url="([^"]+)"/.exec(res.body)[1];
  const cookie = res.cookies[0];
  return { token, statusUrl, cookie: `${cookie.name}=${cookie.value}`, res };
}

export async function pollStatus(app, statusUrl, cookie) {
  const res = await app.inject({ url: statusUrl, headers: { cookie } });
  return { statusCode: res.statusCode, body: res.json(), headers: res.headers };
}

/**
 * Full browser + Telegram login. Returns the authorization code.
 * @param {{ app: any, ctx: any }} idp
 */
export async function login(idp, { user = tgUser(), scope, state = 'xyz', nonce, clientId = 'test-client' } = {}) {
  const { verifier, challenge } = pkce();
  const params = { code_challenge: challenge, state, client_id: clientId };
  if (scope) params.scope = scope;
  if (nonce) params.nonce = nonce;
  const { token, statusUrl, cookie } = await startLogin(idp.app, params);
  const outcome = await idp.ctx.oauth.beginTelegramLogin(token, user);
  if (outcome.kind === 'consent') {
    if (!idp.ctx.oauth.approveLogin(outcome.authRequestId, user)) throw new Error('approve failed');
  } else if (outcome.kind !== 'approved') {
    throw new Error(`login not approved: ${outcome.kind}`);
  }
  const status = await pollStatus(idp.app, statusUrl, cookie);
  const redirectTo = new URL(status.body.redirect_to);
  return { code: redirectTo.searchParams.get('code'), verifier, redirectTo, outcome };
}

export function form(body) {
  return {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(body).toString(),
  };
}

export async function postForm(app, url, body, headers = {}) {
  const f = form(body);
  return app.inject({ method: 'POST', url, headers: { ...f.headers, ...headers }, payload: f.payload });
}

export async function exchangeCode(app, { code, verifier, clientId = 'test-client', redirectUri = REDIRECT_URI, extra = {} }) {
  return postForm(app, '/token', {
    grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri, client_id: clientId, ...extra,
  });
}

export async function refreshGrant(app, refreshToken, clientId = 'test-client', extra = {}) {
  return postForm(app, '/token', { grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId, ...extra });
}

/** Login + code exchange → token response body. Asks for offline_access so a refresh token is issued. */
export async function loginAndExchange(idp, opts = {}) {
  const { code, verifier } = await login(idp, { scope: 'openid profile telegram offline_access', ...opts });
  const res = await exchangeCode(idp.app, { code, verifier, clientId: opts.clientId });
  if (res.statusCode !== 200) throw new Error(`token exchange failed: ${res.body}`);
  return res.json();
}

export function basicAuth(id, secret) {
  const enc = (s) => encodeURIComponent(s);
  return `Basic ${Buffer.from(`${enc(id)}:${enc(secret)}`).toString('base64')}`;
}
