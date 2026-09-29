import crypto from 'node:crypto';
import { mkdir, readFile, readdir, writeFile, rename } from 'node:fs/promises';
import path from 'node:path';
import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';

/** @typedef {import('./types.js').KeyStore} KeyStore */

const ALG = 'RS256';
const ACTIVE_FILE = 'active';

/**
 * @param {crypto.KeyObject} privateKey
 * @returns {Promise<{ kid: string, privateKey: crypto.KeyObject, publicKey: crypto.KeyObject, jwk: object }>}
 */
async function describeKey(privateKey) {
  const publicKey = crypto.createPublicKey(privateKey);
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk, 'sha256');
  return { kid, privateKey, publicKey, jwk: { ...jwk, kid, use: 'sig', alg: ALG } };
}

/**
 * In-memory key set. Every key is published in the JWKS and accepted for
 * verification; only the active key signs. This is what makes rollover
 * possible: publish a new key, wait for client JWKS caches to refresh,
 * activate it, and retire the old one once its tokens have expired.
 * @param {crypto.KeyObject[]} privateKeys
 * @param {string} [activeKid]
 */
export async function createKeySet(privateKeys, activeKid) {
  const entries = new Map();
  for (const pk of privateKeys) {
    const d = await describeKey(pk);
    entries.set(d.kid, d);
  }
  if (entries.size === 0) throw new Error('Key set is empty');
  const active = activeKid ?? (entries.size === 1 ? [...entries.keys()][0] : undefined);
  if (!active || !entries.has(active)) {
    throw new Error(`Active signing key ${active ?? '(unset)'} is not in the key set`);
  }
  return {
    activeKid: active,
    kids: [...entries.keys()],
    /** @type {KeyStore['getSigningKey']} */
    async getSigningKey() {
      const e = entries.get(active);
      return { kid: e.kid, alg: ALG, privateKey: e.privateKey };
    },
    /** @type {KeyStore['getVerificationKey']} */
    async getVerificationKey(kid) {
      // Tokens minted before kids were introduced carry none; accept only when unambiguous.
      if (!kid) return entries.size === 1 ? entries.get(active).publicKey : null;
      return entries.get(kid)?.publicKey ?? null;
    },
    /** @type {KeyStore['getJwks']} */
    async getJwks() {
      return { keys: [...entries.values()].map((e) => e.jwk) };
    },
  };
}

/** Ephemeral single-key store, for tests and embedders that bring their own persistence. */
export async function createMemoryKeyStore() {
  const { privateKey } = await generateKeyPair(ALG, { extractable: true });
  return createKeySet([/** @type {crypto.KeyObject} */ (privateKey)]);
}

/**
 * File-backed key store. Layout of `dir`:
 *   <kid>.pem   PKCS#8 RSA private keys (mode 0600); all are published in the JWKS
 *   active      the kid that signs new tokens
 *   private.pem legacy single key from earlier versions (still loaded)
 * Keys are read once; restart (or call `reload()`) after rotating.
 * @param {string} dir
 * @param {{ generateIfMissing?: boolean }} [options]
 */
export async function createFileKeyStore(dir, options = {}) {
  const { generateIfMissing = true } = options;
  let current = await loadKeyDir(dir, generateIfMissing);
  return {
    get activeKid() { return current.activeKid; },
    get kids() { return current.kids; },
    async reload() { current = await loadKeyDir(dir, false); },
    /** @type {KeyStore['getSigningKey']} */
    getSigningKey: () => current.getSigningKey(),
    /** @type {KeyStore['getVerificationKey']} */
    getVerificationKey: (kid) => current.getVerificationKey(kid),
    /** @type {KeyStore['getJwks']} */
    getJwks: () => current.getJwks(),
  };
}

async function loadKeyDir(dir, generateIfMissing) {
  await mkdir(dir, { recursive: true });
  let files = await listPrivateKeyFiles(dir);
  if (files.length === 0) {
    if (!generateIfMissing) throw new Error(`No signing keys found in ${dir}`);
    const kid = await generateKeyFile(dir);
    await setActiveKey(dir, kid);
    files = await listPrivateKeyFiles(dir);
  }
  const keys = [];
  for (const f of files) {
    const pem = await readFile(path.join(dir, f), 'utf8');
    keys.push(crypto.createPrivateKey(pem));
  }
  const activeKid = await readActiveKid(dir);
  return createKeySet(keys, activeKid);
}

async function listPrivateKeyFiles(dir) {
  const names = await readdir(dir);
  return names.filter((n) => n.endsWith('.pem') && n !== 'public.pem').sort();
}

async function readActiveKid(dir) {
  try {
    return (await readFile(path.join(dir, ACTIVE_FILE), 'utf8')).trim() || undefined;
  } catch (err) {
    if (err.code === 'ENOENT') return undefined;
    throw err;
  }
}

/**
 * Generate a new key in `dir` without activating it (so it can be pre-published).
 * @param {string} dir
 * @returns {Promise<string>} the new kid
 */
export async function generateKeyFile(dir) {
  await mkdir(dir, { recursive: true });
  const { privateKey } = await generateKeyPair(ALG, { extractable: true });
  const { kid } = await describeKey(/** @type {crypto.KeyObject} */ (privateKey));
  const pem = /** @type {crypto.KeyObject} */ (privateKey).export({ type: 'pkcs8', format: 'pem' });
  await writeFile(path.join(dir, `${kid}.pem`), pem, { mode: 0o600, flag: 'wx' });
  return kid;
}

/**
 * @param {string} dir
 * @param {string} kid
 */
export async function setActiveKey(dir, kid) {
  const tmp = path.join(dir, `${ACTIVE_FILE}.tmp`);
  await writeFile(tmp, `${kid}\n`, { mode: 0o600 });
  await rename(tmp, path.join(dir, ACTIVE_FILE));
}

/**
 * List keys in `dir` with their kids and file names.
 * @param {string} dir
 */
export async function describeKeyDir(dir) {
  const files = await listPrivateKeyFiles(dir);
  const active = await readActiveKid(dir);
  const out = [];
  for (const file of files) {
    const { kid } = await describeKey(crypto.createPrivateKey(await readFile(path.join(dir, file), 'utf8')));
    out.push({ kid, file, active: kid === active || (!active && files.length === 1) });
  }
  return out;
}
