# node-guardrails

Three small, dependency-free guards against production failure modes that pass
every code review — because the code looks correct, and *is* correct, until
some quantity crosses a threshold or the deployment topology changes.

Each one below is a bug that shipped, survived review, and was found in
production. Zero dependencies, Node ≥ 18, ESM.

```bash
npm install node-guardrails
```

---

## 1. `Math.max(0, ...values)` is a time bomb

```js
const busiest = Math.max(0, ...countsByUser.values());
```

Every element becomes a **function argument**. Above roughly 65k arguments V8
throws `RangeError: Maximum call stack size exceeded`. The code is correct for
years, then one day a collection gets big enough and the endpoint starts
throwing — usually for your largest customer, because they are the one with the
most data.

```js
import { maxOfValues } from "node-guardrails/safe-max";

const busiest = maxOfValues(countsByUser.values());
```

Also skips `NaN` instead of propagating it. `Math.max` returns `NaN` if *any*
argument is `NaN`, which then silently poisons every downstream calculation.

The test suite includes a 200k-element case that asserts the spread version
actually throws — run `npm test` to see it fail on purpose.

---

## 2. Rate limiting silently degrades behind a reverse proxy

```js
const key = request.socket.remoteAddress;   // the proxy, not the client
```

`socket.remoteAddress` is whoever opened the TCP connection. Behind nginx,
Caddy, a load balancer or Cloudflare Tunnel that is **always the proxy**. Your
per-IP limiter becomes one global bucket shared by every visitor: a single
client can exhaust the quota for everyone, and the limiter looks healthy the
entire time.

The naive fix is worse:

```js
const key = request.headers["x-forwarded-for"];  // attacker-controlled
```

Now anyone mints unlimited buckets by varying the header and bypasses the
limiter completely.

Only the operator knows whether a trusted proxy actually sits in front and
overwrites that header, so it must be opt-in:

```js
import { RateLimiter } from "node-guardrails/client-ip";

// Directly exposed: headers ignored, socket address used.
const limiter = new RateLimiter({ limit: 240 });

// Behind Cloudflare: trust its header explicitly.
const limiter = new RateLimiter({ limit: 240, trustedHeader: "cf-connecting-ip" });
```

Handles the `X-Forwarded-For` list format (`client, proxy1, proxy2` → takes the
left-most entry), falls back to the socket address when the header is absent,
and bounds its own memory.

---

## 3. Sessions that die on every deploy

An in-process `Map` of session IDs works fine — until the process restarts.
Every deploy, crash and blue-green cutover logs all your users out. Teams live
with it for years because the perceived fix is "add Redis".

Often you don't need one. If the session only has to carry *"this bearer proved
they hold the shared secret, until time T"*, sign it:

```js
import { StatelessSessions } from "node-guardrails/stateless-session";

const sessions = new StatelessSessions({ secret: process.env.AUTH_TOKEN });

const { token, expiresAt } = sessions.issue();   // set as an HttpOnly cookie
sessions.verify(token);                          // survives restarts
```

The signing key is derived from a secret you already have, so tokens stay
verifiable across restarts and all become invalid the moment you rotate it.

**Accept these trade-offs before using it:** no per-session revocation
(rotating the secret kills all sessions at once), expiry is baked into the token
and cannot be extended server-side, and anyone holding the token can use it —
so HTTPS only, HttpOnly cookie, short lifetimes. If you need per-session
revocation, use a real store.

---

## Tests

```bash
npm test
```

The tests are written as executable documentation of each failure mode: they
assert that the *broken* idiom really breaks, then that the guard fixes it.

## License

MIT
