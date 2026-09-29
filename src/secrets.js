import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { safeEqual, sha256Hex } from './util.js';

const scrypt = /** @type {(pw: crypto.BinaryLike, salt: crypto.BinaryLike, keylen: number, opts: crypto.ScryptOptions) => Promise<Buffer>} */ (
  promisify(crypto.scrypt)
);

// OWASP-recommended scrypt parameters (N=2^15, r=8, p=1 ≈ 32 MiB).
const PARAMS = { N: 2 ** 15, r: 8, p: 1 };
const KEYLEN = 32;
const maxmem = (N, r) => 128 * N * r * 2;

/**
 * Hash a client secret for storage: `scrypt$N$r$p$salt$hash` (base64url).
 * @param {string} secret
 */
export async function hashSecret(secret) {
  const salt = crypto.randomBytes(16);
  const { N, r, p } = PARAMS;
  const key = await scrypt(secret, salt, KEYLEN, { N, r, p, maxmem: maxmem(N, r) });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${key.toString('base64url')}`;
}

/**
 * Verify a secret against a stored hash. Also accepts the legacy unsalted
 * SHA-256 hex format so existing clients keep working; `needsRehash` tells the
 * caller to upgrade the stored value.
 * @param {string} secret
 * @param {string} stored
 * @returns {Promise<{ ok: boolean, needsRehash: boolean }>}
 */
export async function verifySecret(secret, stored) {
  if (typeof secret !== 'string' || typeof stored !== 'string') return { ok: false, needsRehash: false };
  if (stored.startsWith('scrypt$')) {
    const [, n, r, p, salt, hash] = stored.split('$');
    const N = Number(n), R = Number(r), P = Number(p);
    const expected = Buffer.from(hash, 'base64url');
    const actual = await scrypt(secret, Buffer.from(salt, 'base64url'), expected.length, {
      N, r: R, p: P, maxmem: maxmem(N, R),
    });
    const ok = crypto.timingSafeEqual(actual, expected);
    return { ok, needsRehash: ok && (N !== PARAMS.N || R !== PARAMS.r || P !== PARAMS.p) };
  }
  if (/^[0-9a-f]{64}$/i.test(stored)) {
    const ok = safeEqual(sha256Hex(secret), stored.toLowerCase());
    return { ok, needsRehash: ok };
  }
  return { ok: false, needsRehash: false };
}
