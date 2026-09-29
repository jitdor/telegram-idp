import crypto from 'node:crypto';

/** @typedef {import('./types.js').Clock} Clock */

/** Wall clock in epoch seconds — the unit used for every timestamp in the IdP. */
/** @type {Clock} */
export const systemClock = { now: () => Math.floor(Date.now() / 1000) };

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** @param {string} value */
export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** @param {string} value */
export function sha256Base64url(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

/**
 * Constant-time string comparison (length is not secret).
 * @param {string} a
 * @param {string} b
 */
export function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

const DURATION_UNITS = { '': 1, s: 1, m: 60, h: 3600, d: 86400 };

/**
 * Parse "90", "90s", "15m", "12h", "30d" (or a number) into seconds.
 * @param {string | number} value
 * @returns {number}
 */
export function parseDuration(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) return Math.floor(value);
  const m = /^(\d+)\s*([smhd]?)$/.exec(String(value).trim());
  if (!m) throw new Error(`Invalid duration: ${value}`);
  return Number(m[1]) * DURATION_UNITS[m[2]];
}

/**
 * Normalize a scope value (space separated string, JSON array string, or array)
 * into a de-duplicated array.
 * @param {string | string[] | null | undefined} value
 * @returns {string[]}
 */
export function splitScopes(value) {
  if (!value) return [];
  let list;
  if (Array.isArray(value)) {
    list = value;
  } else {
    const s = String(value).trim();
    list = s.startsWith('[') ? JSON.parse(s) : s.split(/\s+/);
  }
  return [...new Set(list.map(String).filter(Boolean))];
}

/** @param {unknown} value */
export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
