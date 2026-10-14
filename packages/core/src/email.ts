/**
 * Normalizes an email for storage and lookup: trims surrounding whitespace and lowercases it.
 *
 * Uses `toLowerCase()` rather than `toLocaleLowerCase()` so the result does not depend on the
 * server's locale (e.g. Turkish dotted/dotless i).
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
