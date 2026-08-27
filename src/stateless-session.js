/**
 * Sessions that survive a restart, without a session store.
 *
 * Keeping sessions in an in-process `Map` is the default in small services and
 * works fine — until the process restarts. Every deploy, every crash, every
 * blue-green cutover logs all your users out. On a service that deploys often
 * this is a steady, low-grade annoyance that nobody ever gets around to fixing
 * because "we'd have to add Redis".
 *
 * You usually don't. If the only thing the session needs to carry is "this
 * bearer proved they hold the shared secret, until time T", a signed token does
 * the job with no storage at all: derive a signing key from the secret you
 * already have, and the signature stays verifiable across restarts.
 *
 * Trade-offs you are accepting:
 *   - No server-side revocation of an individual session. Rotating the
 *     underlying secret invalidates all of them at once.
 *   - The expiry is inside the token, so it cannot be extended server-side.
 *   - Anyone holding the token can use it. Send it over HTTPS, store it in an
 *     HttpOnly cookie, keep lifetimes short.
 *
 * If you need per-session revocation or server-controlled expiry, you do need
 * a store — use one.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;

export class StatelessSessions {
  /**
   * @param {object} options
   * @param {string} options.secret Shared secret. The signing key is derived
   *   from it, so sessions stay valid across restarts and die when it rotates.
   * @param {number} [options.ttlMs=43200000] Session lifetime (default 12h).
   * @param {string} [options.namespace="session-v1"] Domain separator, so the
   *   same secret used elsewhere produces unrelated keys.
   * @param {() => number} [options.now] Injectable clock, for tests.
   */
  constructor({ secret, ttlMs = DEFAULT_TTL_MS, namespace = "session-v1", now = () => Date.now() } = {}) {
    if (!secret) throw new Error("StatelessSessions requires a secret");
    this.key = createHash("sha256").update(`${namespace}:${secret}`).digest();
    this.ttlMs = Math.max(1, Number(ttlMs) || DEFAULT_TTL_MS);
    this.now = now;
  }

  /** @returns {{token: string, expiresAt: number}} */
  issue() {
    const expiresAt = this.now() + this.ttlMs;
    return { token: this.sign(expiresAt), expiresAt };
  }

  /** @param {number} expiresAt @returns {string} `<expiry>.<signature>` */
  sign(expiresAt) {
    const payload = String(expiresAt);
    return `${payload}.${this.hmac(payload)}`;
  }

  /** @param {string} token @returns {boolean} */
  verify(token) {
    const raw = String(token || "");
    // base64url never contains ".", so the last one separates payload from signature.
    const separator = raw.lastIndexOf(".");
    if (separator <= 0) return false;
    const payload = raw.slice(0, separator);
    if (!safeEqual(raw.slice(separator + 1), this.hmac(payload))) return false;
    const expiresAt = Number(payload);
    return Number.isFinite(expiresAt) && expiresAt > this.now();
  }

  hmac(payload) {
    return createHmac("sha256", this.key).update(payload).digest("base64url");
  }
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left ?? ""));
  const b = Buffer.from(String(right ?? ""));
  // timingSafeEqual throws on length mismatch, so compare lengths first.
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}
