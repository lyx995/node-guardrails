/**
 * Finding the maximum of a large collection without blowing the stack.
 *
 * The idiom `Math.max(0, ...values)` is common and looks harmless, but every
 * element becomes a separate function argument. V8 throws
 * `RangeError: Maximum call stack size exceeded` somewhere above ~65k
 * arguments (the exact limit depends on the engine, platform and available
 * stack), so the bug only appears once your data grows — typically in
 * production, on your biggest customer, at the worst time.
 *
 * This is a silent time bomb: the code is correct for years, then one day a
 * collection crosses the threshold and an entire endpoint starts throwing.
 */

/**
 * Returns the largest finite number in `values`, or `floor` if there is none.
 *
 * Differences from `Math.max(floor, ...values)`:
 *   - No argument-count limit: works for collections of any size.
 *   - Non-finite entries (NaN, Infinity, null, undefined, non-numeric strings)
 *     are skipped rather than poisoning the result. `Math.max` returns NaN if
 *     any argument is NaN, which then silently propagates through every
 *     downstream calculation.
 *
 * @param {Iterable<unknown>} values Any iterable: Array, Map.values(), Set, generator.
 * @param {number} [floor=0] Returned when no finite value is present.
 * @returns {number}
 */
export function maxOfValues(values, floor = 0) {
  let max = floor;
  for (const value of values || []) {
    const number = Number(value);
    if (Number.isFinite(number) && number > max) max = number;
  }
  return max;
}

/**
 * Mirror of {@link maxOfValues} for minimums.
 *
 * @param {Iterable<unknown>} values
 * @param {number} [ceiling=Number.POSITIVE_INFINITY]
 * @returns {number}
 */
export function minOfValues(values, ceiling = Number.POSITIVE_INFINITY) {
  let min = ceiling;
  for (const value of values || []) {
    const number = Number(value);
    if (Number.isFinite(number) && number < min) min = number;
  }
  return min;
}
