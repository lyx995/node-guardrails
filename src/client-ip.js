/**
 * Resolving the real client IP behind a reverse proxy — without opening a
 * spoofing hole.
 *
 * `request.socket.remoteAddress` is the address of whoever opened the TCP
 * connection. Behind a proxy (nginx, Caddy, Cloudflare Tunnel, a load
 * balancer) that is always the proxy itself. Per-IP rate limiting keyed on it
 * silently degrades into a single global bucket shared by every visitor: one
 * client can exhaust the quota for everyone, and the limiter looks like it is
 * working the whole time.
 *
 * The naive fix — always trust `X-Forwarded-For` — is worse: that header is
 * attacker-controlled, so anyone can mint unlimited buckets by varying it and
 * bypass the limiter entirely.
 *
 * The rule: only read a forwarding header when the operator has explicitly
 * named one, because only the operator knows a trusted proxy actually sits in
 * front and overwrites it.
 */

/**
 * @param {object} [options]
 * @param {string} [options.trustedHeader]
 *   Header to trust, e.g. "cf-connecting-ip" or "x-forwarded-for". Leave unset
 *   (the default) when the app is directly exposed — then headers are ignored.
 * @returns {(request: {headers?: Record<string, unknown>, socket?: {remoteAddress?: string}}) => string}
 */
export function createClientIpResolver({ trustedHeader = "" } = {}) {
  const header = String(trustedHeader || "").trim().toLowerCase();

  return function resolveClientIp(request) {
    if (header) {
      const raw = request?.headers?.[header];
      // X-Forwarded-For is a list: "client, proxy1, proxy2".
      // The left-most entry is the original client.
      const first = String(raw ?? "").split(",")[0].trim();
      if (first) return first;
    }
    return String(request?.socket?.remoteAddress || "unknown");
  };
}

/**
 * Minimal fixed-window rate limiter keyed by resolved client IP.
 *
 * Fixed windows allow up to 2x the limit across a window boundary; that is an
 * accepted trade-off for O(1) memory per client. Use a sliding window or token
 * bucket if you need a strict guarantee.
 */
export class RateLimiter {
  /**
   * @param {object} [options]
   * @param {number} [options.limit=240] Requests allowed per window.
   * @param {number} [options.windowMs=60000]
   * @param {string} [options.trustedHeader] Passed to {@link createClientIpResolver}.
   * @param {() => number} [options.now] Injectable clock, for tests.
   */
  constructor({ limit = 240, windowMs = 60_000, trustedHeader = "", now = () => Date.now() } = {}) {
    this.limit = Math.max(1, Number(limit) || 1);
    this.windowMs = Math.max(1, Number(windowMs) || 1);
    this.resolveClientIp = createClientIpResolver({ trustedHeader });
    this.now = now;
    this.windows = new Map();
  }

  /** @returns {boolean} true if the request is allowed. */
  allow(request) {
    const now = this.now();
    const key = this.resolveClientIp(request);
    let window = this.windows.get(key);
    if (!window || now - window.startedAt >= this.windowMs) {
      window = { startedAt: now, count: 0 };
      this.windows.set(key, window);
    }
    window.count += 1;
    // Bound memory: without this a hostile client can grow the map forever.
    if (this.windows.size > 5_000) this.prune(now);
    return window.count <= this.limit;
  }

  prune(now = this.now()) {
    for (const [key, window] of this.windows) {
      if (now - window.startedAt > this.windowMs * 2) this.windows.delete(key);
    }
  }
}
