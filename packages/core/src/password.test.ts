import { hash as argon2Hash } from '@node-rs/argon2';
import { describe, expect, it } from 'vitest';
import { isLychgateError } from './errors.js';
import type { PasswordPolicyError } from './errors.js';
import {
  ARGON2ID_DEFAULTS,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  hashPassword,
  needsRehash,
  verifyPassword,
} from './password.js';

const PASSWORD = 'correct horse battery staple';

async function policyError(plain: unknown): Promise<PasswordPolicyError> {
  const error: unknown = await hashPassword(plain as string).catch((e: unknown) => e);
  if (!isLychgateError(error, 'INVALID_PASSWORD_POLICY')) {
    throw new Error('expected a password policy error');
  }
  return error as PasswordPolicyError;
}

describe('hashPassword / verifyPassword', () => {
  it('round-trips a password using argon2id with the default parameters', async () => {
    const hash = await hashPassword(PASSWORD);

    expect(hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await verifyPassword(hash, PASSWORD)).toBe(true);
  });

  it('salts every hash', async () => {
    expect(await hashPassword(PASSWORD)).not.toBe(await hashPassword(PASSWORD));
  });

  it('rejects a wrong password', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(await verifyPassword(hash, 'correct horse battery stapler')).toBe(false);
  });

  it('treats differently-encoded but identical Unicode passwords as equal (NFC)', async () => {
    const composed = 'café-password'; // é as one code point
    const decomposed = 'café-password'; // e + combining acute accent
    const hash = await hashPassword(composed);
    expect(await verifyPassword(hash, decomposed)).toBe(true);
  });

  it.each([
    ['an empty string', ''],
    ['garbage', 'not-a-hash'],
    ['a truncated argon2 hash', '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA'],
    ['a bcrypt hash', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'],
    ['a non-string', 42 as unknown as string],
  ])('returns false (never throws) for a malformed hash: %s', async (_label, badHash) => {
    expect(await verifyPassword(badHash, PASSWORD)).toBe(false);
  });

  it('returns false for a non-string password', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(await verifyPassword(hash, undefined as unknown as string)).toBe(false);
  });

  it('returns false for an oversized password without hashing it', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(await verifyPassword(hash, 'a'.repeat(PASSWORD_MAX_LENGTH + 1))).toBe(false);
  });
});

describe('password policy', () => {
  it(`accepts exactly ${String(PASSWORD_MIN_LENGTH)} and ${String(PASSWORD_MAX_LENGTH)} characters`, async () => {
    await expect(hashPassword('a'.repeat(PASSWORD_MIN_LENGTH))).resolves.toMatch(/^\$argon2id\$/);
    await expect(hashPassword('a'.repeat(PASSWORD_MAX_LENGTH))).resolves.toMatch(/^\$argon2id\$/);
  });

  it('rejects passwords that are too short', async () => {
    expect((await policyError('a'.repeat(PASSWORD_MIN_LENGTH - 1))).reason).toBe('TOO_SHORT');
  });

  it('rejects passwords that are too long', async () => {
    expect((await policyError('a'.repeat(PASSWORD_MAX_LENGTH + 1))).reason).toBe('TOO_LONG');
  });

  it('rejects non-strings', async () => {
    expect((await policyError(null)).reason).toBe('NOT_A_STRING');
    expect((await policyError(12345678)).reason).toBe('NOT_A_STRING');
  });

  it('counts characters, not UTF-16 code units', async () => {
    // Each emoji is 2 UTF-16 code units but 1 character.
    await expect(hashPassword('🔑'.repeat(PASSWORD_MIN_LENGTH))).resolves.toMatch(/^\$argon2id\$/);
    expect((await policyError('🔑'.repeat(PASSWORD_MIN_LENGTH - 1))).reason).toBe('TOO_SHORT');
  });

  it('never includes the password in the error', async () => {
    const secret = 'hunter2';
    const error = await policyError(secret);
    expect(error.message).not.toContain(secret);
    expect(String(error)).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
  });
});

describe('hash options', () => {
  it('uses the OWASP defaults', () => {
    expect(ARGON2ID_DEFAULTS).toEqual({ memoryCost: 19_456, timeCost: 2, parallelism: 1 });
  });

  it('accepts custom parameters at or above the OWASP minimums', async () => {
    const hash = await hashPassword(PASSWORD, { memoryCost: 12_288, timeCost: 3 });
    expect(hash).toMatch(/\$m=12288,t=3,p=1\$/);
    expect(await verifyPassword(hash, PASSWORD)).toBe(true);
  });

  it.each([
    [{ memoryCost: 1024 }],
    [{ timeCost: 1 }], // t=1 needs m >= 47104
    [{ timeCost: 0 }],
    [{ parallelism: 1.5 }],
  ])('rejects weak or invalid parameters: %o', async (options) => {
    const error: unknown = await hashPassword(PASSWORD, options).catch((e: unknown) => e);
    expect(isLychgateError(error, 'INVALID_HASH_OPTIONS')).toBe(true);
  });
});

describe('needsRehash', () => {
  it('returns false for a hash made with the current parameters', async () => {
    expect(needsRehash(await hashPassword(PASSWORD))).toBe(false);
  });

  it('returns true when the parameters have changed', async () => {
    const hash = await hashPassword(PASSWORD);
    expect(needsRehash(hash, { memoryCost: 12_288, timeCost: 3 })).toBe(true);
    expect(needsRehash(hash, { memoryCost: 32_768 })).toBe(true);
  });

  it('returns false when the stored hash matches custom parameters', async () => {
    const options = { memoryCost: 12_288, timeCost: 3 };
    expect(needsRehash(await hashPassword(PASSWORD, options), options)).toBe(false);
  });

  it('returns true for a hash that is not argon2id', async () => {
    // 1 = Algorithm.Argon2i (an ambient const enum, so it can't be imported as a value).
    // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-assignment
    const argon2iHash = await argon2Hash(PASSWORD, { ...ARGON2ID_DEFAULTS, algorithm: 1 });
    expect(argon2iHash).toMatch(/^\$argon2i\$/);
    expect(needsRehash(argon2iHash)).toBe(true);
  });

  it('returns true for a malformed hash', () => {
    expect(needsRehash('not-a-hash')).toBe(true);
    expect(needsRehash('')).toBe(true);
  });
});
