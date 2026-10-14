import { hash, parseOptions, verify } from '@node-rs/argon2';
import type { Algorithm, Version } from '@node-rs/argon2';
import { LychgateError, PasswordPolicyError } from './errors.js';

export const PASSWORD_MIN_LENGTH = 8;
/** Caps the work an attacker can force per request by sending huge "passwords" (hashing DoS). */
export const PASSWORD_MAX_LENGTH = 128;

/**
 * Default argon2id cost, matching OWASP's Password Storage Cheat Sheet recommendation:
 * 19 MiB of memory, 2 iterations, 1 degree of parallelism.
 */
export const ARGON2ID_DEFAULTS = {
  /** In KiB. */
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
} as const;

export interface HashOptions {
  /** Memory cost in KiB. */
  memoryCost?: number;
  /** Number of iterations. */
  timeCost?: number;
  parallelism?: number;
}

// @node-rs/argon2 exposes these as ambient `const enum`s, which can't be imported as values
// under `isolatedModules`. The types still check that the numbers are valid members.
// eslint-disable-next-line @typescript-eslint/no-unsafe-enum-assignment -- see above
const ARGON2ID: Algorithm = 2;
// eslint-disable-next-line @typescript-eslint/no-unsafe-enum-assignment -- see above
const ARGON2_VERSION_0x13: Version = 1;

/**
 * OWASP lists equally strong argon2id configurations that trade memory for iterations.
 * Returns the minimum memory (KiB) OWASP allows for a given number of iterations.
 */
function owaspMinimumMemoryCost(timeCost: number): number {
  if (timeCost <= 1) return 47_104;
  if (timeCost === 2) return 19_456;
  if (timeCost === 3) return 12_288;
  if (timeCost === 4) return 9_216;
  return 7_168;
}

function resolveHashOptions(options: HashOptions = {}): Required<HashOptions> {
  const resolved = { ...ARGON2ID_DEFAULTS, ...options };
  const { memoryCost, timeCost, parallelism } = resolved;

  if (![memoryCost, timeCost, parallelism].every((n) => Number.isInteger(n) && n >= 1)) {
    throw new LychgateError('INVALID_HASH_OPTIONS', 'Hash options must be positive integers.');
  }
  const minimumMemory = owaspMinimumMemoryCost(timeCost);
  if (memoryCost < minimumMemory) {
    throw new LychgateError(
      'INVALID_HASH_OPTIONS',
      `memoryCost ${String(memoryCost)} KiB is below the OWASP minimum of ${String(minimumMemory)} KiB for timeCost ${String(timeCost)}.`,
    );
  }
  return resolved;
}

/**
 * Normalizes to Unicode NFC so the same password typed on different keyboards/OSes (which may
 * encode accented characters differently) produces the same hash.
 */
function normalizePassword(plain: string): string {
  return plain.normalize('NFC');
}

/**
 * Counts Unicode code points, so an emoji counts as one character, not two UTF-16 units.
 * Code points (not graphemes) on purpose: each is at most 4 bytes, so the max length also
 * bounds the bytes we hash.
 */
function characterCount(value: string): number {
  // eslint-disable-next-line @typescript-eslint/no-misused-spread -- code points are intended
  return [...value].length;
}

/** Throws `PasswordPolicyError` if a new password is not acceptable. */
function assertPasswordPolicy(password: unknown): asserts password is string {
  // Callers often pass request bodies straight through, so check the type at runtime too.
  if (typeof password !== 'string') {
    throw new PasswordPolicyError('NOT_A_STRING', 'Password must be a string.');
  }
  const length = characterCount(normalizePassword(password));
  if (length < PASSWORD_MIN_LENGTH) {
    throw new PasswordPolicyError(
      'TOO_SHORT',
      `Password must be at least ${String(PASSWORD_MIN_LENGTH)} characters.`,
    );
  }
  if (length > PASSWORD_MAX_LENGTH) {
    throw new PasswordPolicyError(
      'TOO_LONG',
      `Password must be at most ${String(PASSWORD_MAX_LENGTH)} characters.`,
    );
  }
}

/**
 * Hashes a new password with argon2id. Validates the password policy first and throws
 * `PasswordPolicyError` if it fails. Returns a PHC string that embeds the salt and parameters.
 */
export async function hashPassword(plain: string, options?: HashOptions): Promise<string> {
  const params = resolveHashOptions(options);
  assertPasswordPolicy(plain);
  return hash(normalizePassword(plain), {
    ...params,
    algorithm: ARGON2ID,
    version: ARGON2_VERSION_0x13,
  });
}

/**
 * Checks a password against a stored hash. Never throws: anything wrong with the input
 * (malformed hash, non-string, oversized password) resolves to `false`.
 *
 * Only the maximum length is enforced here, not the minimum, so tightening the minimum later
 * does not lock out users with older, shorter passwords.
 */
export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  if (typeof hash !== 'string' || typeof plain !== 'string') return false;
  const password = normalizePassword(plain);
  if (characterCount(password) > PASSWORD_MAX_LENGTH) return false;
  try {
    return await verify(hash, password);
  } catch {
    return false;
  }
}

/**
 * Returns `true` if a stored hash should be replaced with a fresh one, because it is not argon2id
 * or was made with different parameters than the current ones. Call it after a successful
 * login and, if it returns `true`, re-hash the password the user just supplied.
 */
export function needsRehash(hash: string, options?: HashOptions): boolean {
  const current = resolveHashOptions(options);
  if (typeof hash !== 'string') return true;
  try {
    const stored = parseOptions(hash);
    return (
      stored.algorithm !== ARGON2ID ||
      stored.version !== ARGON2_VERSION_0x13 ||
      stored.memoryCost !== current.memoryCost ||
      stored.timeCost !== current.timeCost ||
      stored.parallelism !== current.parallelism
    );
  } catch {
    return true;
  }
}
