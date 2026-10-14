import { LychgateError } from './errors.js';

/** RFC 5321 caps a forward path at 256 octets, which leaves 254 for the address itself. */
export const EMAIL_MAX_LENGTH = 254;

/**
 * Normalizes an email for storage and lookup: trims surrounding whitespace and lowercases it.
 *
 * Uses `toLowerCase()` rather than `toLocaleLowerCase()` so the result does not depend on the
 * server's locale (e.g. Turkish dotted/dotless i).
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Normalizes an email and applies basic sanity checks, throwing `INVALID_EMAIL` if they fail.
 *
 * Deliberately not a full RFC 5322 parser: the only real proof that an address works is
 * sending mail to it (email verification is planned for v2).
 */
export function parseEmail(input: unknown): string {
  if (typeof input !== 'string') throw invalidEmail();
  const email = normalizeEmail(input);

  const parts = email.split('@');
  const hasOneAt = parts.length === 2 && parts.every((part) => part.length > 0);
  if (!hasOneAt || email.length > EMAIL_MAX_LENGTH || /\s/.test(email)) throw invalidEmail();

  return email;
}

function invalidEmail(): LychgateError {
  // The address is not echoed back: errors end up in logs.
  return new LychgateError('INVALID_EMAIL', 'Email address is not valid.');
}
