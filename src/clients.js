import { SUPPORTED_SCOPES } from './config.js';
import { validatePolicy } from './policy.js';
import { hashSecret } from './secrets.js';
import { randomToken, splitScopes } from './util.js';

/**
 * Registered redirect URIs must be absolute, fragment-free, and HTTPS unless
 * they point at loopback (native/dev clients) or use a private-use scheme.
 * @param {string} uri
 */
export function validateRedirectUri(uri) {
  let url;
  try {
    url = new URL(uri);
  } catch {
    throw new Error(`Redirect URI is not an absolute URL: ${uri}`);
  }
  if (url.hash) throw new Error(`Redirect URI must not contain a fragment: ${uri}`);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol === 'http:' && !loopback) throw new Error(`Redirect URI must use https: ${uri}`);
  if (url.protocol === 'javascript:' || url.protocol === 'data:') throw new Error(`Unsafe redirect URI scheme: ${uri}`);
}

/**
 * Validate and store (create or replace) a client.
 * @param {import('./store.js').Store} store
 * @param {object} input
 * @param {string} input.clientId
 * @param {string} input.name
 * @param {string[]} input.redirectUris
 * @param {string[] | string} [input.scopes]
 * @param {string | null} [input.secret] plaintext secret for a confidential client
 * @param {boolean} [input.generateSecret] generate a random secret (returned once)
 * @param {object | null} [input.policy]
 * @param {boolean} [input.firstParty]
 * @param {number} [now] epoch seconds
 * @returns {Promise<{ clientId: string, secret: string | null }>}
 */
export async function registerClient(store, input, now = Math.floor(Date.now() / 1000)) {
  const clientId = String(input.clientId || '').trim();
  if (!/^[A-Za-z0-9._~-]{1,128}$/.test(clientId)) {
    throw new Error('client_id must be 1-128 characters of A-Z a-z 0-9 . _ ~ -');
  }
  const name = String(input.name || '').trim();
  if (!name) throw new Error('Client name is required');
  const redirectUris = (input.redirectUris || []).map((u) => String(u).trim()).filter(Boolean);
  if (redirectUris.length === 0) throw new Error('At least one redirect URI is required');
  redirectUris.forEach(validateRedirectUri);

  const scopes = splitScopes(input.scopes ?? SUPPORTED_SCOPES.join(' '));
  const unknown = scopes.filter((s) => !SUPPORTED_SCOPES.includes(s));
  if (unknown.length) throw new Error(`Unsupported scopes: ${unknown.join(' ')} (supported: ${SUPPORTED_SCOPES.join(' ')})`);
  if (scopes.length === 0) throw new Error('At least one scope is required');

  validatePolicy(input.policy ?? null);

  let secret = input.secret ? String(input.secret) : null;
  if (input.generateSecret) secret = randomToken(32);
  if (secret !== null && secret.length < 16) throw new Error('Client secrets must be at least 16 characters');

  store.upsertClient({
    clientId,
    name,
    secretHash: secret ? await hashSecret(secret) : null,
    redirectUris,
    allowedScopes: scopes,
    policy: input.policy ?? null,
    isFirstParty: !!input.firstParty,
  }, now);
  return { clientId, secret };
}
