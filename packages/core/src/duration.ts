/** A number of seconds, or a string like `"30s"`, `"15m"`, `"12h"` or `"30d"`. */
export type Duration = number | `${number}${'s' | 'm' | 'h' | 'd'}`;

const SECONDS_PER_UNIT = { s: 1, m: 60, h: 60 * 60, d: 24 * 60 * 60 } as const;

/** Converts a `Duration` to whole seconds. Returns `null` if it is not a positive whole duration. */
export function parseDuration(value: unknown): number | null {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value > 0 ? value : null;
  }
  if (typeof value !== 'string') return null;

  const match = /^(\d+)([smhd])$/.exec(value);
  if (!match) return null;
  const [, amount, unit] = match as unknown as [string, string, keyof typeof SECONDS_PER_UNIT];

  const seconds = Number(amount) * SECONDS_PER_UNIT[unit];
  return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : null;
}
