import test from "node:test";
import assert from "node:assert/strict";
import { createClientIpResolver, RateLimiter } from "../src/client-ip.js";

const req = (headers = {}, remoteAddress = "10.0.0.7") => ({ headers, socket: { remoteAddress } });

test("ignores forwarding headers unless one is explicitly trusted", () => {
  const resolve = createClientIpResolver();
  assert.equal(resolve(req({ "x-forwarded-for": "1.2.3.4" })), "10.0.0.7");
  assert.equal(resolve(req({ "cf-connecting-ip": "1.2.3.4" })), "10.0.0.7");
});

test("spoofed headers cannot create extra rate-limit buckets", () => {
  const limiter = new RateLimiter({ limit: 10 });
  let allowed = 0;
  for (let i = 0; i < 25; i += 1) {
    if (limiter.allow(req({ "x-forwarded-for": `9.9.9.${i}` }))) allowed += 1;
  }
  assert.equal(allowed, 10, "all spoofed requests share the socket-address bucket");
});

test("uses the trusted header and takes the left-most entry", () => {
  const resolve = createClientIpResolver({ trustedHeader: "X-Forwarded-For" });
  assert.equal(resolve(req({ "x-forwarded-for": "5.6.7.8, 10.0.0.1, 172.16.0.1" })), "5.6.7.8");
  // Falls back when the proxy did not set it, rather than lumping everyone together.
  assert.equal(resolve(req({})), "10.0.0.7");
});

test("distinct real clients get independent buckets", () => {
  const limiter = new RateLimiter({ limit: 10, trustedHeader: "cf-connecting-ip" });
  let allowed = 0;
  for (let i = 0; i < 25; i += 1) {
    if (limiter.allow(req({ "cf-connecting-ip": `203.0.113.${i}` }))) allowed += 1;
  }
  assert.equal(allowed, 25);
});

test("window resets and memory stays bounded", () => {
  let clock = 0;
  const limiter = new RateLimiter({ limit: 2, windowMs: 1000, now: () => clock });
  assert.equal(limiter.allow(req()), true);
  assert.equal(limiter.allow(req()), true);
  assert.equal(limiter.allow(req()), false);
  clock += 1001;
  assert.equal(limiter.allow(req()), true, "new window");
  clock += 5000;
  limiter.prune();
  assert.equal(limiter.windows.size, 0, "stale windows are dropped");
});
