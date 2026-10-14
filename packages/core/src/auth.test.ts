import { describe, expect, it } from 'vitest';
import type { Adapter } from './adapter.js';
import { memoryAdapter } from './adapters/memory.js';
import { rehashPassword } from './password.js';
import { EMAIL, PASSWORD, setup, sha256 } from './test-helpers.js';

const FIFTEEN_MINUTES = 15 * 60;
const THIRTY_DAYS = 30 * 24 * 60 * 60;

async function withUser(...args: Parameters<typeof setup>) {
  const context = setup(...args);
  await context.auth.register({ email: EMAIL, password: PASSWORD });
  return context;
}

describe('register', () => {
  it('creates a user with a normalized email and never returns the hash', async () => {
    const { auth, adapter } = setup();
    const user = await auth.register({ email: '  Alice@Example.COM ', password: PASSWORD });

    expect(user).toEqual({
      id: expect.any(String) as string,
      email: EMAIL,
      roles: [],
      createdAt: expect.any(Date) as Date,
      updatedAt: expect.any(Date) as Date,
    });
    expect(user).not.toHaveProperty('passwordHash');
    expect((await adapter.findUserById(user.id))?.passwordHash).toMatch(/^\$argon2id\$/);
  });

  it('rejects a duplicate email, whatever its case, with EMAIL_TAKEN', async () => {
    const { auth } = await withUser();
    await expect(
      auth.register({ email: 'ALICE@example.com', password: PASSWORD }),
    ).rejects.toMatchObject({
      code: 'EMAIL_TAKEN',
    });
  });

  it.each([
    ['empty', ''],
    ['only whitespace', '   '],
    ['no @', 'alice.example.com'],
    ['two @', 'alice@@example.com'],
    ['@ in domain', 'alice@example@com'],
    ['empty local part', '@example.com'],
    ['empty domain', 'alice@'],
    ['inner whitespace', 'al ice@example.com'],
    ['too long', `${'a'.repeat(250)}@x.io`],
    ['not a string', 42],
  ])('rejects an invalid email (%s) with INVALID_EMAIL', async (_label, email) => {
    const { auth } = setup();
    await expect(
      auth.register({ email: email as string, password: PASSWORD }),
    ).rejects.toMatchObject({
      code: 'INVALID_EMAIL',
    });
  });

  it.each([
    ['too short', 'short'],
    ['too long', 'a'.repeat(129)],
    ['not a string', undefined],
  ])('rejects a password that is %s and creates no user', async (_label, password) => {
    const { auth, adapter } = setup();
    await expect(
      auth.register({ email: EMAIL, password: password as string }),
    ).rejects.toMatchObject({
      code: 'INVALID_PASSWORD_POLICY',
    });
    expect(await adapter.findUserByEmail(EMAIL)).toBeNull();
  });
});

describe('login', () => {
  it('returns a session with an access token and a refresh token', async () => {
    const { auth, clock } = await withUser();
    const session = await auth.login({ email: ' ALICE@example.com', password: PASSWORD });
    const now = clock.now().getTime();

    expect(session.user.email).toBe(EMAIL);
    expect(session.user).not.toHaveProperty('passwordHash');
    expect(session.expiresAt).toEqual(new Date(now + FIFTEEN_MINUTES * 1000));
    expect(session.refreshTokenExpiresAt).toEqual(new Date(now + THIRTY_DAYS * 1000));
    // 32 random bytes, base64url-encoded.
    expect(session.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const claims = await auth.verifyAccessToken(session.accessToken);
    expect(claims.userId).toBe(session.user.id);
    expect(claims.roles).toEqual([]);
  });

  it('starts a new token family on every login', async () => {
    const { auth, adapter } = await withUser();
    const first = await auth.login({ email: EMAIL, password: PASSWORD });
    const second = await auth.login({ email: EMAIL, password: PASSWORD });

    const a = await adapter.findRefreshTokenByHash(sha256(first.refreshToken));
    const b = await adapter.findRefreshTokenByHash(sha256(second.refreshToken));
    expect(a?.familyId).toBeDefined();
    expect(a?.familyId).not.toBe(b?.familyId);
  });

  it('gives the same INVALID_CREDENTIALS error for a wrong password, an unknown user and a passwordless user', async () => {
    const { auth, adapter } = await withUser();
    await adapter.createUser({
      id: 'oauth-user',
      email: 'oauth@example.com',
      passwordHash: null,
      roles: [],
    });

    const errors = await Promise.all([
      auth.login({ email: EMAIL, password: 'wrong password!' }).catch((e: unknown) => e),
      auth.login({ email: 'nobody@example.com', password: PASSWORD }).catch((e: unknown) => e),
      auth.login({ email: 'oauth@example.com', password: PASSWORD }).catch((e: unknown) => e),
      auth.login(null as never).catch((e: unknown) => e),
    ]);

    for (const error of errors) {
      expect(error).toMatchObject({
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password.',
      });
    }
  });

  it('upgrades an outdated password hash after a successful login', async () => {
    const adapter = memoryAdapter();
    const weaker = { memoryCost: 12_288, timeCost: 3 };
    const { auth: oldAuth } = setup({ adapter, passwordHashing: weaker });
    const user = await oldAuth.register({ email: EMAIL, password: PASSWORD });
    expect((await adapter.findUserById(user.id))?.passwordHash).toContain('$m=12288,t=3,p=1$');

    const { auth: newAuth } = setup({ adapter }); // OWASP defaults
    await newAuth.login({ email: EMAIL, password: PASSWORD });

    const upgraded = (await adapter.findUserById(user.id))?.passwordHash;
    expect(upgraded).toContain('$m=19456,t=2,p=1$');
    // The new hash still works, and doesn't get rehashed again.
    await newAuth.login({ email: EMAIL, password: PASSWORD });
    expect((await adapter.findUserById(user.id))?.passwordHash).toBe(upgraded);
  });

  it('can rehash a legacy password that is shorter than the current minimum', async () => {
    const adapter = memoryAdapter();
    const legacyHash = await rehashPassword('short', { memoryCost: 12_288, timeCost: 3 });
    await adapter.createUser({ id: 'legacy', email: EMAIL, passwordHash: legacyHash, roles: [] });

    const { auth } = setup({ adapter });
    await expect(auth.login({ email: EMAIL, password: 'short' })).resolves.toBeDefined();
    expect((await adapter.findUserById('legacy'))?.passwordHash).toContain('$m=19456,t=2,p=1$');
  });
});

describe('refresh', () => {
  async function loggedIn(...args: Parameters<typeof setup>) {
    const context = await withUser(...args);
    const session = await context.auth.login({ email: EMAIL, password: PASSWORD });
    const recordOf = (refreshToken: string) =>
      context.adapter.findRefreshTokenByHash(sha256(refreshToken));
    return { ...context, session, recordOf };
  }

  it('rotates: returns new tokens, revokes the old one and keeps the family', async () => {
    const { auth, clock, session, recordOf } = await loggedIn();
    clock.advance(60);
    const next = await auth.refresh(session.refreshToken);

    expect(next.refreshToken).not.toBe(session.refreshToken);
    expect(next.accessToken).not.toBe(session.accessToken);
    expect((await auth.verifyAccessToken(next.accessToken)).userId).toBe(session.user.id);

    const oldRecord = await recordOf(session.refreshToken);
    const newRecord = await recordOf(next.refreshToken);
    expect(oldRecord?.revokedAt).toEqual(clock.now());
    expect(oldRecord?.replacedById).toBe(newRecord?.id);
    expect(newRecord?.familyId).toBe(oldRecord?.familyId);
    expect(newRecord?.revokedAt).toBeNull();
  });

  it('slides the refresh token expiry forward on each rotation', async () => {
    const { auth, clock, session } = await loggedIn();
    clock.advance(THIRTY_DAYS - 60);
    const next = await auth.refresh(session.refreshToken);
    expect(next.refreshTokenExpiresAt).toEqual(
      new Date(clock.now().getTime() + THIRTY_DAYS * 1000),
    );

    clock.advance(THIRTY_DAYS - 60);
    await expect(auth.refresh(next.refreshToken)).resolves.toBeDefined();
  });

  it('rejects an expired refresh token with REFRESH_TOKEN_EXPIRED', async () => {
    const { auth, clock, session } = await loggedIn();
    clock.advance(THIRTY_DAYS);
    await expect(auth.refresh(session.refreshToken)).rejects.toMatchObject({
      code: 'REFRESH_TOKEN_EXPIRED',
    });
  });

  it.each([
    ['an unknown token', 'x'.repeat(43)],
    ['an empty string', ''],
    ['an oversized string', 'x'.repeat(10_000)],
    ['a non-string', 123],
  ])('rejects %s with INVALID_REFRESH_TOKEN', async (_label, token) => {
    const { auth } = await loggedIn();
    await expect(auth.refresh(token as string)).rejects.toMatchObject({
      code: 'INVALID_REFRESH_TOKEN',
    });
  });

  it('picks up role changes on refresh', async () => {
    const { auth, adapter, session } = await loggedIn();
    await adapter.updateUser(session.user.id, { roles: ['admin'] });

    expect((await auth.verifyAccessToken(session.accessToken)).roles).toEqual([]);
    const next = await auth.refresh(session.refreshToken);
    expect((await auth.verifyAccessToken(next.accessToken)).roles).toEqual(['admin']);
  });

  describe('reuse detection', () => {
    it('revokes the whole family, including the newest legitimate token, when a rotated token is replayed', async () => {
      const { auth, adapter, session, recordOf } = await loggedIn();
      const other = await auth.login({ email: EMAIL, password: PASSWORD }); // separate family
      const second = await auth.refresh(session.refreshToken);
      const third = await auth.refresh(second.refreshToken);

      await expect(auth.refresh(session.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });

      expect((await recordOf(third.refreshToken))?.revokedAt).not.toBeNull();
      expect(
        await adapter.isFamilyRevoked((await recordOf(third.refreshToken))?.familyId ?? ''),
      ).toBe(true);
      await expect(auth.refresh(third.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });
      // Other sessions are unaffected.
      await expect(auth.refresh(other.refreshToken)).resolves.toBeDefined();
    });

    it('lets exactly one of two simultaneous refreshes succeed, and kills the family (strict)', async () => {
      const { auth, session } = await loggedIn();
      const results = await Promise.allSettled([
        auth.refresh(session.refreshToken),
        auth.refresh(session.refreshToken),
      ]);

      const winners = results.filter((r) => r.status === 'fulfilled');
      const losers = results.filter((r) => r.status === 'rejected');
      expect(winners).toHaveLength(1);
      expect(losers).toHaveLength(1);
      expect(losers[0]?.reason).toMatchObject({ code: 'REFRESH_TOKEN_REUSED' });

      // The winner's new token was created after (or during) the family revocation. It must not work.
      const winner = winners[0];
      if (winner?.status !== 'fulfilled') throw new Error('unreachable');
      await expect(auth.refresh(winner.value.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });
    });

    it('rejects a token that a concurrent refresh created just after the family was revoked', async () => {
      // Force the worst interleaving: the winner's new token is stored only AFTER the loser
      // has finished revoking the family. Revoking existing rows alone would miss that token.
      const inner = memoryAdapter();
      let openGate = () => {};
      const familyRevoked = new Promise<void>((resolve) => (openGate = resolve));
      let holdCreates = false;
      const adapter: Adapter = {
        ...inner,
        async createRefreshToken(input) {
          if (holdCreates) await familyRevoked;
          return inner.createRefreshToken(input);
        },
        async revokeFamily(familyId, revokedAt) {
          await inner.revokeFamily(familyId, revokedAt);
          openGate();
        },
      };
      const { auth, session, recordOf } = await loggedIn({ adapter });

      holdCreates = true;
      const results = await Promise.allSettled([
        auth.refresh(session.refreshToken),
        auth.refresh(session.refreshToken),
      ]);
      const winner = results.find((r) => r.status === 'fulfilled');
      if (!winner) throw new Error('expected one refresh to succeed');

      // The late token was stored un-revoked...
      expect((await recordOf(winner.value.refreshToken))?.revokedAt).toBeNull();
      // ...but its family is marked revoked, so it is refused on first use.
      await expect(auth.refresh(winner.value.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });
    });

    it('lets exactly one of two simultaneous refreshes succeed, keeping the family, with leeway', async () => {
      const { auth, session } = await loggedIn({ refreshReuseLeewaySeconds: 10 });
      const results = await Promise.allSettled([
        auth.refresh(session.refreshToken),
        auth.refresh(session.refreshToken),
      ]);

      const winner = results.find((r) => r.status === 'fulfilled');
      const loser = results.find((r) => r.status === 'rejected');
      expect(loser?.reason).toMatchObject({ code: 'INVALID_REFRESH_TOKEN' });
      if (!winner) throw new Error('expected one refresh to succeed');
      await expect(auth.refresh(winner.value.refreshToken)).resolves.toBeDefined();
    });

    it('inside the leeway, rejects a replay without revoking the family', async () => {
      const { auth, clock, session } = await loggedIn({ refreshReuseLeewaySeconds: 10 });
      const next = await auth.refresh(session.refreshToken);
      clock.advance(9);

      await expect(auth.refresh(session.refreshToken)).rejects.toMatchObject({
        code: 'INVALID_REFRESH_TOKEN',
      });
      await expect(auth.refresh(next.refreshToken)).resolves.toBeDefined();
    });

    it('outside the leeway, a replay revokes the family', async () => {
      const { auth, clock, session } = await loggedIn({ refreshReuseLeewaySeconds: 10 });
      const next = await auth.refresh(session.refreshToken);
      clock.advance(10);

      await expect(auth.refresh(session.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });
      await expect(auth.refresh(next.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });
    });

    it('never applies the leeway to a token revoked by logout', async () => {
      const { auth, adapter, session, recordOf } = await loggedIn({
        refreshReuseLeewaySeconds: 10,
      });
      await auth.logout(session.refreshToken);

      await expect(auth.refresh(session.refreshToken)).rejects.toMatchObject({
        code: 'REFRESH_TOKEN_REUSED',
      });
      expect(
        await adapter.isFamilyRevoked((await recordOf(session.refreshToken))?.familyId ?? ''),
      ).toBe(true);
    });
  });
});

describe('logout', () => {
  it('revokes the whole family and leaves other sessions alone', async () => {
    const { auth, adapter } = await withUser();
    const session = await auth.login({ email: EMAIL, password: PASSWORD });
    const other = await auth.login({ email: EMAIL, password: PASSWORD });
    const rotated = await auth.refresh(session.refreshToken);

    await auth.logout(rotated.refreshToken);

    expect(
      (await adapter.findRefreshTokenByHash(sha256(rotated.refreshToken)))?.revokedAt,
    ).not.toBeNull();
    await expect(auth.refresh(rotated.refreshToken)).rejects.toMatchObject({
      code: 'REFRESH_TOKEN_REUSED',
    });
    await expect(auth.refresh(other.refreshToken)).resolves.toBeDefined();
  });

  it('is idempotent and silent for unknown or junk tokens', async () => {
    const { auth } = await withUser();
    const session = await auth.login({ email: EMAIL, password: PASSWORD });

    await auth.logout(session.refreshToken);
    await expect(auth.logout(session.refreshToken)).resolves.toBeUndefined();
    await expect(auth.logout('never-issued')).resolves.toBeUndefined();
    await expect(auth.logout(undefined as never)).resolves.toBeUndefined();
  });
});
