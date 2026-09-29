/**
 * Fixed-window, in-memory rate limiter. Per process: with several instances
 * behind a load balancer each enforces its own window, so put a shared
 * limiter (proxy or Redis-backed implementation of this interface) in front.
 * @typedef {object} RateLimiter
 * @property {(key: string, max: number, windowSeconds?: number) => { allowed: boolean, retryAfter: number }} hit
 */

/**
 * @param {{ clock: import('./types.js').Clock, maxKeys?: number }} deps
 * @returns {RateLimiter}
 */
export function createRateLimiter({ clock, maxKeys = 100_000 }) {
  /** @type {Map<string, { windowStart: number, count: number }>} */
  const buckets = new Map();

  function sweep(now, windowSeconds) {
    for (const [k, b] of buckets) if (now - b.windowStart >= windowSeconds) buckets.delete(k);
  }

  return {
    hit(key, max, windowSeconds = 60) {
      if (!max) return { allowed: true, retryAfter: 0 };
      const now = clock.now();
      let b = buckets.get(key);
      if (!b || now - b.windowStart >= windowSeconds) {
        if (buckets.size >= maxKeys) sweep(now, windowSeconds);
        b = { windowStart: now, count: 0 };
        buckets.set(key, b);
      }
      b.count += 1;
      if (b.count > max) return { allowed: false, retryAfter: Math.max(1, b.windowStart + windowSeconds - now) };
      return { allowed: true, retryAfter: 0 };
    },
  };
}
