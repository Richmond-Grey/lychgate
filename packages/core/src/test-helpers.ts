/* Shared fixtures for core's own tests. Not part of the package (nothing exports it). */
import { createHash } from 'node:crypto';
import type { Adapter } from './adapter.js';
import { memoryAdapter } from './adapters/memory.js';
import { createAuth } from './auth.js';
import type { AuthConfig } from './config.js';

// Long enough for the HS512 "wrong algorithm" test too.
export const SECRET = 'test-secret-long-enough-for-hs256-and-also-hs512-0123456789abcdef';
export const ISSUER = 'https://auth.example.test';
export const AUDIENCE = 'example-api';
export const EMAIL = 'alice@example.com';
export const PASSWORD = 'correct horse battery staple';

/** A clock that only moves when told to. */
export function fakeClock(start = new Date('2030-01-01T00:00:00.000Z')) {
  let current = start.getTime();
  return {
    now: () => new Date(current),
    advance(seconds: number) {
      current += seconds * 1000;
    },
  };
}

export function setup(overrides: Partial<AuthConfig> = {}) {
  const clock = fakeClock();
  const adapter: Adapter = overrides.adapter ?? memoryAdapter();
  const auth = createAuth({
    secret: SECRET,
    issuer: ISSUER,
    audience: AUDIENCE,
    now: clock.now,
    ...overrides,
    adapter,
  });
  return { auth, adapter, clock };
}

/** Independent of the implementation: refresh tokens must be stored as their SHA-256 hex. */
export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
