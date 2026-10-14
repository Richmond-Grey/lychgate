import { describe, expect, it } from 'vitest';
import { memoryAdapter } from './adapters/memory.js';
import { createAuth } from './auth.js';
import type { AuthConfig } from './config.js';
import { AUDIENCE, ISSUER, SECRET } from './test-helpers.js';

const valid = (): AuthConfig => ({
  adapter: memoryAdapter(),
  secret: SECRET,
  issuer: ISSUER,
  audience: AUDIENCE,
});

describe('createAuth config validation', () => {
  it('accepts a minimal valid config, a 32-byte Uint8Array secret and numeric TTLs', () => {
    expect(() => createAuth(valid())).not.toThrow();
    expect(() =>
      createAuth({
        ...valid(),
        secret: new Uint8Array(32),
        accessTokenTtl: 600,
        refreshTokenTtl: '7d',
      }),
    ).not.toThrow();
  });

  it.each<[string, Partial<Record<keyof AuthConfig, unknown>>]>([
    ['a 31-byte secret', { secret: 'x'.repeat(31) }],
    ['a short Uint8Array secret', { secret: new Uint8Array(16) }],
    ['a missing secret', { secret: undefined }],
    ['a missing adapter', { adapter: undefined }],
    ['an empty issuer', { issuer: '' }],
    ['a missing audience', { audience: undefined }],
    ['an unparseable TTL', { accessTokenTtl: '15 minutes' }],
    ['an unknown TTL unit', { refreshTokenTtl: '2w' }],
    ['a fractional TTL', { accessTokenTtl: '1.5m' }],
    ['a zero TTL', { accessTokenTtl: 0 }],
    ['a negative TTL', { refreshTokenTtl: -60 }],
    ['a negative leeway', { refreshReuseLeewaySeconds: -1 }],
    ['a NaN leeway', { refreshReuseLeewaySeconds: Number.NaN }],
    ['a clock that is not a function', { now: new Date() }],
  ])('rejects %s with INVALID_CONFIG', (_label, override) => {
    expect(() => createAuth({ ...valid(), ...override } as AuthConfig)).toThrow(
      expect.objectContaining({ code: 'INVALID_CONFIG' }) as Error,
    );
  });

  it('rejects weak password hashing options with INVALID_HASH_OPTIONS', () => {
    expect(() => createAuth({ ...valid(), passwordHashing: { memoryCost: 1024 } })).toThrow(
      expect.objectContaining({ code: 'INVALID_HASH_OPTIONS' }) as Error,
    );
  });

  it('never echoes the secret in its error', () => {
    const shortSecret = 'too-short-secret';
    expect(() => createAuth({ ...valid(), secret: shortSecret })).toThrow(
      expect.not.objectContaining({
        message: expect.stringContaining(shortSecret) as string,
      }) as Error,
    );
  });
});
