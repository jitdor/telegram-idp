// Shared JSDoc type definitions. Checked by `npm run typecheck` (tsc --checkJs).
export {};

/**
 * @typedef {object} Clock
 * @property {() => number} now Current time in epoch seconds.
 */

/**
 * @typedef {object} RateLimits Requests per minute per client IP; 0 disables a limit.
 * @property {number} token
 * @property {number} authorize
 * @property {number} status
 * @property {number} introspect
 * @property {number} revoke
 * @property {number} userinfo
 */

/**
 * @typedef {object} IdpConfig All durations are in seconds.
 * @property {number} port
 * @property {string} host
 * @property {string} issuer Public base URL; the `iss` of every token.
 * @property {string | null} telegramBotToken
 * @property {string | null} telegramBotUsername Overrides the username learned from `getMe`.
 * @property {string | null} telegramWebhookSecret
 * @property {string} dbPath
 * @property {string} keysDir
 * @property {number} accessTokenTtl
 * @property {number} idTokenTtl
 * @property {number} refreshTokenTtl
 * @property {number} authRequestTtl
 * @property {number} authCodeTtl
 * @property {boolean} trustProxy
 * @property {boolean} reevaluatePolicyOnRefresh
 * @property {'offline_access' | 'always'} issueRefreshTokens When to issue a refresh token on code exchange.
 * @property {number} refreshReuseGraceSeconds A rotated token replayed within this window only fails
 *   (benign concurrent refresh) instead of revoking the grant. 0 = strict.
 * @property {RateLimits} rateLimits
 */

/**
 * The subset of a Telegram `User` object the IdP reads.
 * @typedef {object} TelegramUser
 * @property {number} id
 * @property {string} [username]
 * @property {string} [first_name]
 * @property {string} [last_name]
 * @property {string} [language_code]
 * @property {boolean} [is_premium]
 * @property {string} [photo_url]
 */

/**
 * @typedef {object} User
 * @property {number} id
 * @property {number} telegram_user_id
 * @property {string | null} telegram_username
 * @property {string | null} first_name
 * @property {string | null} last_name
 * @property {string | null} photo_url
 * @property {string | null} language_code
 * @property {number} is_premium 0 or 1
 * @property {number} created_at
 * @property {number} updated_at
 * @property {number | null} last_login_at
 */

/**
 * @typedef {object} AuthRequestRow
 * @property {string} id
 * @property {string} token_hash
 * @property {string} client_id
 * @property {string} redirect_uri
 * @property {string | null} state
 * @property {string} scope
 * @property {string | null} nonce
 * @property {string} code_challenge
 * @property {string} code_challenge_method
 * @property {'pending' | 'approved' | 'denied'} status
 * @property {number | null} telegram_user_id
 * @property {number | null} user_id
 * @property {string} browser_session_id
 * @property {string | null} error
 * @property {string | null} error_description
 * @property {number} created_at
 * @property {number} expires_at
 */

/**
 * @typedef {object} AuthCodeRow
 * @property {string} code
 * @property {string} auth_request_id
 * @property {number} user_id
 * @property {string} client_id
 * @property {string} redirect_uri
 * @property {string} code_challenge
 * @property {string} code_challenge_method
 * @property {string} scope
 * @property {string | null} nonce
 * @property {number} auth_time
 * @property {number} created_at
 * @property {number} expires_at
 * @property {number | null} used_at
 * @property {string | null} refresh_family_id
 * @property {string | null} access_token_jti
 * @property {number | null} access_token_exp
 */

/**
 * @typedef {object} RefreshTokenRow
 * @property {number} id
 * @property {string} token_hash
 * @property {string} family_id
 * @property {number} user_id
 * @property {string} client_id
 * @property {string} scope
 * @property {number | null} auth_time
 * @property {number} created_at
 * @property {number} expires_at
 * @property {number | null} rotated_at
 * @property {number | null} revoked_at
 */

/**
 * @typedef {object} Client
 * @property {string} clientId
 * @property {string} name
 * @property {string | null} secretHash
 * @property {string[]} redirectUris
 * @property {string[]} allowedScopes
 * @property {PolicyNode | null} policy
 * @property {boolean} isFirstParty
 */

/**
 * @typedef {{ operator: 'and' | 'or', conditions: PolicyNode[] }
 *   | { operator: 'not', condition: PolicyNode }
 *   | { type: string, [key: string]: any }} PolicyNode
 */

/**
 * @typedef {object} PolicyResult
 * @property {boolean} pass
 * @property {string} [reason]
 */

/**
 * Narrow view of the Telegram Bot API the core needs. `grammy`'s `bot.api` satisfies it.
 * @typedef {object} TelegramApi
 * @property {(chatId: number | string, userId: number) => Promise<{ status: string }>} getChatMember
 */

/**
 * @typedef {object} SigningKey
 * @property {string} kid
 * @property {'RS256'} alg
 * @property {import('node:crypto').KeyObject} privateKey
 */

/**
 * Source of signing keys. The file store is the default; a KMS/HSM backed
 * implementation only has to satisfy this interface.
 * @typedef {object} KeyStore
 * @property {() => Promise<SigningKey>} getSigningKey
 * @property {(kid: string | undefined) => Promise<import('node:crypto').KeyObject | null>} getVerificationKey
 * @property {() => Promise<{ keys: object[] }>} getJwks
 */

/**
 * @typedef {object} Logger
 * @property {(obj: any, msg?: string) => void} info
 * @property {(obj: any, msg?: string) => void} warn
 * @property {(obj: any, msg?: string) => void} error
 */

/**
 * @typedef {object} IdpContext Everything a request handler needs; created by `createIdpContext`.
 * @property {Readonly<IdpConfig>} config
 * @property {import('./store.js').Store} store
 * @property {KeyStore} keys
 * @property {TelegramApi | null} telegram
 * @property {() => string | null} getBotUsername
 * @property {Clock} clock
 * @property {Logger} logger
 * @property {import('./tokens.js').TokenService} tokens
 * @property {import('./oauth.js').OAuthService} oauth
 */
