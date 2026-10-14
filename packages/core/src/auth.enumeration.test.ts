/*
 * Login must not reveal whether an email is registered: the same error AND the same hashing
 * work in every failure case. This file replaces verifyPassword with a spy that still calls
 * the real thing, so we can see exactly which hash each login verified against.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import type * as PasswordModule from './password.js';
import { verifyPassword } from './password.js';
import { EMAIL, PASSWORD, setup } from './test-helpers.js';

vi.mock('./password.js', async (importOriginal) => {
  const actual = await importOriginal<typeof PasswordModule>();
  return { ...actual, verifyPassword: vi.fn(actual.verifyPassword) };
});

const verifySpy = vi.mocked(verifyPassword);
const DEFAULT_PARAMS = /^\$argon2id\$v=19\$m=19456,t=2,p=1\$/;

describe('login does not leak whether an account exists', () => {
  afterEach(() => {
    verifySpy.mockClear();
  });

  it.each([
    ['wrong password', EMAIL, 'wrong password!'],
    ['unknown user', 'nobody@example.com', PASSWORD],
    ['user without a password', 'oauth@example.com', PASSWORD],
  ])('%s: one full argon2id verification, generic error', async (_label, email, password) => {
    const { auth, adapter } = setup();
    await auth.register({ email: EMAIL, password: PASSWORD });
    await adapter.createUser({
      id: 'oauth',
      email: 'oauth@example.com',
      passwordHash: null,
      roles: [],
    });
    verifySpy.mockClear();

    await expect(auth.login({ email, password })).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password.',
    });

    expect(verifySpy).toHaveBeenCalledTimes(1);
    const [hash, plain] = verifySpy.mock.calls[0] ?? [];
    // A real, same-cost hash (not an empty string that would fail fast), and the real password.
    expect(hash).toMatch(DEFAULT_PARAMS);
    expect(plain).toBe(password);
    expect(await verifySpy.mock.results[0]?.value).toBe(false);
  });
});
