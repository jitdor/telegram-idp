// Library entry point. Nothing here reads the environment or opens files at
// import time; `createIdp` wires an instance from explicit options.
import { registerBotHandlers } from './bot.js';
import { defineConfig } from './config.js';
import { createIdpContext } from './context.js';
import { createDatabase } from './db.js';
import { buildApp } from './http/app.js';
import { createFileKeyStore } from './keys.js';

export { buildApp } from './http/app.js';
export { createBotHandlers, registerBotHandlers, createTelegramBot } from './bot.js';
export { defineConfig, loadConfig, SUPPORTED_SCOPES, DEFAULT_SCOPES } from './config.js';
export { createIdpContext } from './context.js';
export { createDatabase, SCHEMA_VERSION } from './db.js';
export { OAuthError, UnsafeRedirectError } from './errors.js';
export { createFileKeyStore, createMemoryKeyStore, createKeySet, generateKeyFile, setActiveKey } from './keys.js';
export { evaluatePolicy, validatePolicy } from './policy.js';
export { createRateLimiter } from './rate-limit.js';
export { hashSecret, verifySecret } from './secrets.js';
export { createSqliteStore } from './store.js';
export { createTokenService } from './tokens.js';
export { registerClient } from './clients.js';

/**
 * Convenience factory: config + (optional) db, keys and grammY bot → a ready
 * Fastify app. Anything not supplied is created from the config.
 * @param {object} [options]
 * @param {Readonly<import('./types.js').IdpConfig> | Partial<import('./types.js').IdpConfig>} [options.config]
 * @param {import('node:sqlite').DatabaseSync} [options.db]
 * @param {import('./types.js').KeyStore} [options.keys]
 * @param {import('grammy').Bot} [options.bot] handlers are registered on it
 * @param {import('./types.js').Clock} [options.clock]
 * @param {boolean | object} [options.logger]
 * @param {number} [options.maintenanceIntervalMs]
 */
export async function createIdp(options = {}) {
  const config = Object.isFrozen(options.config) ? /** @type {any} */ (options.config) : defineConfig(options.config);
  const db = options.db ?? createDatabase(config.dbPath);
  const keys = options.keys ?? await createFileKeyStore(config.keysDir);
  const bot = options.bot ?? null;
  // The Fastify logger only exists once the app is built; forward to it lazily.
  /** @type {any} */
  let appLog = null;
  const logger = {
    info: (o, m) => appLog?.info(o, m),
    warn: (o, m) => appLog?.warn(o, m),
    error: (o, m) => appLog?.error(o, m),
  };
  const ctx = createIdpContext({
    logger,
    config,
    db,
    keys,
    clock: options.clock,
    telegram: bot ? bot.api : null,
    getBotUsername: () => config.telegramBotUsername || (bot?.isInited() ? bot.botInfo.username : null),
  });
  if (bot) registerBotHandlers(bot, ctx);
  const app = await buildApp(ctx, {
    logger: options.logger,
    bot,
    maintenanceIntervalMs: options.maintenanceIntervalMs,
  });
  appLog = app.log;
  return { ctx, app, bot, db };
}
