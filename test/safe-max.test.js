import test from "node:test";
import assert from "node:assert/strict";
import { maxOfValues, minOfValues } from "../src/safe-max.js";

test("handles collections far beyond the argument-spread limit", () => {
  const huge = new Map();
  for (let i = 0; i < 200_000; i += 1) huge.set(`key-${i}`, i % 97);

  // Demonstrate the bug this module exists to prevent.
  let spreadThrew = false;
  try {
    Math.max(0, ...huge.values());
  } catch (error) {
    spreadThrew = error instanceof RangeError;
  }
  assert.equal(spreadThrew, true, "Math.max(...spread) should blow up at this size");

  // The safe version just works.
  assert.equal(maxOfValues(huge.values()), 96);
});

test("skips non-finite values instead of propagating NaN", () => {
  assert.equal(maxOfValues([Number.NaN, 3, "7", null, undefined]), 7);
  assert.ok(Number.isNaN(Math.max(0, Number.NaN, 3)), "Math.max poisons the result");
});

test("respects the floor and handles empty input", () => {
  assert.equal(maxOfValues([]), 0);
  assert.equal(maxOfValues(undefined), 0);
  assert.equal(maxOfValues([-5, -2]), 0, "floor wins when all values are below it");
  assert.equal(maxOfValues([-5, -2], -Infinity), -2);
});

test("minOfValues mirrors the behaviour", () => {
  assert.equal(minOfValues([4, 2, 9]), 2);
  assert.equal(minOfValues([Number.NaN, 4, "2"]), 2);
  assert.equal(minOfValues([]), Number.POSITIVE_INFINITY);
});
