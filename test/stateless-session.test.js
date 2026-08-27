import test from "node:test";
import assert from "node:assert/strict";
import { StatelessSessions } from "../src/stateless-session.js";

const SECRET = "a".repeat(40);

test("a session issued before a restart still verifies after it", () => {
  const before = new StatelessSessions({ secret: SECRET });
  const { token } = before.issue();
  // A fresh instance is exactly what a restarted process looks like.
  const after = new StatelessSessions({ secret: SECRET });
  assert.equal(after.verify(token), true);
});

test("rotating the secret invalidates every existing session", () => {
  const { token } = new StatelessSessions({ secret: SECRET }).issue();
  assert.equal(new StatelessSessions({ secret: "b".repeat(40) }).verify(token), false);
});

test("rejects tampering, garbage and expiry", () => {
  let clock = 1_000_000;
  const sessions = new StatelessSessions({ secret: SECRET, ttlMs: 1000, now: () => clock });
  const { token } = sessions.issue();
  assert.equal(sessions.verify(token), true);

  // Extend the expiry but keep the original signature.
  const [, signature] = token.split(".");
  assert.equal(sessions.verify(`${clock + 999_999}.${signature}`), false);

  assert.equal(sessions.verify("garbage"), false);
  assert.equal(sessions.verify(""), false);
  assert.equal(sessions.verify(null), false);
  assert.equal(sessions.verify(`${clock + 500}.`), false);

  clock += 1001;
  assert.equal(sessions.verify(token), false, "expired");
});

test("namespace separates keys derived from the same secret", () => {
  const a = new StatelessSessions({ secret: SECRET, namespace: "api" });
  const b = new StatelessSessions({ secret: SECRET, namespace: "admin" });
  assert.equal(b.verify(a.issue().token), false);
});

test("requires a secret", () => {
  assert.throws(() => new StatelessSessions({}), /requires a secret/);
});
