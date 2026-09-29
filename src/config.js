import { parseDuration } from './util.js';

/** @typedef {import('./types.js').IdpConfig} IdpConfig */

/** Scopes this IdP knows how to honour. Clients may be restricted to a subset. */
export const SUPPORTED_SCOPES = Object.freeze(['openid', 'profile', 'telegram', 'offline_access']);

/** Scope used when `/authorize` is called without `scope` (intersected with the client's allowed scopes). */
export const DEFAULT_SCOPES = Object.freeze(['openid', 'profile', 'telegram']);

/** @type {IdpConfig} */
const DEFAULTS = {
  port: 3000,
  host: '0.0.0.0',
  issuer: 'http://localhost:3000',
  telegramBotToken: null,
  telegramBotUsername: null,
  telegramWebhookSecret: null,
  dbPath: './data.db',
  keysDir: './keys',
  accessTokenTtl: 15 * 60,
  idTokenTtl: 15 * 60,
  refreshTokenTtl: 30 * 86400,
  authRequestTtl: 120,
  authCodeTtl: 60,
  trustProxy: false,
  reevaluatePolicyOnRefresh: true,
  rateLimits: { token: 30, authorize: 30, status: 120, introspect: 120, revoke: 60, userinfo: 120 },
};

/**
 * Build an immutable config from explicit values (no environment access).
 * This is what library embedders should use.
 * @param {Partial<IdpConfig>} [values]
 * @returns {Readonly<IdpConfig>}
 */
export function defineConfig(values = {}) {
  const merged = {
    ...DEFAULTS,
    ...stripUndefined(values),
    rateLimits: { ...DEFAULTS.rateLimits, ...stripUndefined(values.rateLimits || {}) },
  };
  merged.issuer = String(merged.issuer).replace(/\/+$/, '');
  for (const key of ['accessTokenTtl', 'idTokenTtl', 'refreshTokenTtl', 'authRequestTtl', 'authCodeTtl']) {
    merged[key] = parseDuration(merged[key]);
  }
  Object.freeze(merged.rateLimits);
  return Object.freeze(merged);
}

/**
 * Read configuration from environment variables.
 * @param {Record<string, string | undefined>} [env]
 * @returns {Readonly<IdpConfig>}
 */
export function loadConfig(env = process.env) {
  return defineConfig({
    port: env.PORT ? Number(env.PORT) : undefined,
    host: env.HOST,
    issuer: env.BASE_URL,
    telegramBotToken: env.TELEGRAM_BOT_TOKEN,
    telegramBotUsername: env.TELEGRAM_BOT_USERNAME,
    telegramWebhookSecret: env.TELEGRAM_WEBHOOK_SECRET,
    dbPath: env.DB_PATH,
    keysDir: env.KEYS_DIR,
    accessTokenTtl: env.ACCESS_TOKEN_TTL,
    idTokenTtl: env.ID_TOKEN_TTL,
    refreshTokenTtl: env.REFRESH_TOKEN_TTL,
    authRequestTtl: env.AUTH_REQUEST_TTL,
    authCodeTtl: env.AUTH_CODE_TTL,
    trustProxy: bool(env.TRUST_PROXY),
    reevaluatePolicyOnRefresh: bool(env.REEVALUATE_POLICY_ON_REFRESH),
    rateLimits: {
      token: int(env.RATE_LIMIT_TOKEN),
      authorize: int(env.RATE_LIMIT_AUTHORIZE),
      status: int(env.RATE_LIMIT_STATUS),
      introspect: int(env.RATE_LIMIT_INTROSPECT),
      revoke: int(env.RATE_LIMIT_REVOKE),
      userinfo: int(env.RATE_LIMIT_USERINFO),
    },
  });
}

function bool(v) {
  if (v === undefined || v === '') return undefined;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function int(v) {
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`Expected a non-negative integer, got ${v}`);
  return n;
}

function stripUndefined(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));
}
