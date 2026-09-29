import { createOAuthService } from './oauth.js';
import { createSqliteStore } from './store.js';
import { createTokenService } from './tokens.js';
import { systemClock } from './util.js';

/** @typedef {import('./types.js').IdpContext} IdpContext */

const silentLogger = { info() {}, warn() {}, error() {} };

/**
 * Wire an IdP instance from injected dependencies. Nothing here is global:
 * several contexts (different issuers, databases, keys) can live in one process.
 *
 * @param {object} deps
 * @param {Readonly<import('./types.js').IdpConfig>} deps.config
 * @param {import('./types.js').KeyStore} deps.keys
 * @param {import('node:sqlite').DatabaseSync} [deps.db] used to build the default store
 * @param {import('./store.js').Store} [deps.store]
 * @param {import('./types.js').TelegramApi | null} [deps.telegram] for policy group checks
 * @param {() => string | null} [deps.getBotUsername] defaults to `config.telegramBotUsername`
 * @param {import('./types.js').Clock} [deps.clock]
 * @param {import('./types.js').Logger} [deps.logger]
 * @returns {IdpContext}
 */
export function createIdpContext(deps) {
  const { config, keys } = deps;
  if (!config) throw new Error('createIdpContext: config is required');
  if (!keys) throw new Error('createIdpContext: keys is required');
  const store = deps.store ?? (deps.db ? createSqliteStore(deps.db) : null);
  if (!store) throw new Error('createIdpContext: db or store is required');
  const clock = deps.clock ?? systemClock;

  const base = {
    config,
    store,
    keys,
    telegram: deps.telegram ?? null,
    getBotUsername: deps.getBotUsername ?? (() => config.telegramBotUsername),
    clock,
    logger: deps.logger ?? silentLogger,
    tokens: createTokenService({ config, keys, clock }),
  };
  return { ...base, oauth: createOAuthService(base) };
}
