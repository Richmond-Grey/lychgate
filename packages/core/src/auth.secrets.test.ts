/*
 * Secrets must never end up where they could be logged or leaked: not in errors, and not in
 * anything handed to the storage adapter (only hashes of refresh tokens are stored).
 */
import { describe, expect, it } from 'vitest';
import type { Adapter } from './adapter.js';
import { memoryAdapter } from './adapters/memory.js';
import { EMAIL, PASSWORD, setup, sha256 } from './test-helpers.js';

/** Wraps an adapter and records every argument and result that passes through it. */
function recordingAdapter(inner: Adapter): { adapter: Adapter; traffic: unknown[] } {
  const traffic: unknown[] = [];
  const wrapped = Object.fromEntries(
    Object.entries(inner).map(([name, method]) => [
      name,
      async (...args: unknown[]) => {
        traffic.push(name, args);
        const result: unknown = await (method as (...a: unknown[]) => Promise<unknown>)(...args);
        traffic.push(result);
        return result;
      },
    ]),
  );
  return { adapter: wrapped as unknown as Adapter, traffic };
}

/** Everything about an error that might reach a log line. */
function describeError(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  return [
    error.message,
    String(error),
    error.stack,
    JSON.stringify(error),
    String(error.cause),
  ].join('\n');
}

describe('secrets never leak', () => {
  it('keeps passwords, hashes and raw refresh tokens out of errors and adapter traffic', async () => {
    const { adapter, traffic } = recordingAdapter(memoryAdapter());
    const { auth, clock } = setup({ adapter });

    await auth.register({ email: EMAIL, password: PASSWORD });
    const first = await auth.login({ email: EMAIL, password: PASSWORD });
    const second = await auth.refresh(first.refreshToken);
    const passwordHash = (await adapter.findUserByEmail(EMAIL))?.passwordHash ?? '';
    const rawTokens = [first.refreshToken, second.refreshToken];

    const tooShortPassword = 'hunter2';
    const failures = [
      auth.register({ email: EMAIL, password: PASSWORD }),
      auth.register({ email: 'new@example.com', password: tooShortPassword }),
      auth.register({ email: 'not an email', password: PASSWORD }),
      auth.login({ email: EMAIL, password: `${PASSWORD}!` }),
      auth.refresh(`${first.refreshToken}x`),
      auth.refresh(first.refreshToken), // reuse
      auth.verifyAccessToken(`${second.accessToken}x`),
    ];
    clock.advance(31 * 24 * 60 * 60);
    failures.push(auth.refresh(second.refreshToken)); // revoked by the reuse above

    const errors = await Promise.all(
      failures.map((p) =>
        p.then(
          () => null,
          (e: unknown) => e,
        ),
      ),
    );
    expect(errors).not.toContain(null);

    const errorText = errors.map(describeError).join('\n');
    const trafficText = JSON.stringify(traffic);
    for (const secret of [PASSWORD, tooShortPassword, `${PASSWORD}!`, passwordHash, ...rawTokens]) {
      expect(errorText).not.toContain(secret);
    }
    for (const secret of [PASSWORD, tooShortPassword, `${PASSWORD}!`, ...rawTokens]) {
      expect(trafficText).not.toContain(secret);
    }

    // What IS stored for each refresh token is its SHA-256.
    for (const raw of rawTokens) {
      expect(await adapter.findRefreshTokenByHash(sha256(raw))).not.toBeNull();
    }
  });
});
