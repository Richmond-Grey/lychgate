import { randomUUID } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import type { Adapter, CreateRefreshTokenInput, CreateUserInput } from '../adapter.js';
import { isLychgateError } from '../errors.js';

/** Returns a fresh, empty adapter. Called before every test. */
export type AdapterFactory = () => Adapter | Promise<Adapter>;

const HOUR_MS = 60 * 60 * 1000;

function userInput(overrides: Partial<CreateUserInput> = {}): CreateUserInput {
  return {
    id: randomUUID(),
    email: `user-${randomUUID()}@example.com`,
    passwordHash: '$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g',
    roles: ['user'],
    ...overrides,
  };
}

function tokenInput(
  userId: string,
  overrides: Partial<CreateRefreshTokenInput> = {},
): CreateRefreshTokenInput {
  return {
    id: randomUUID(),
    userId,
    familyId: randomUUID(),
    tokenHash: randomUUID(),
    expiresAt: new Date(Date.now() + HOUR_MS),
    ...overrides,
  };
}

function isEmailTaken(error: unknown): boolean {
  return isLychgateError(error, 'EMAIL_TAKEN');
}

/**
 * The behaviour every Lychgate adapter must have. Call it from a Vitest test file:
 *
 * ```ts
 * import { runAdapterContractTests } from '@lychgate/core/testing';
 * runAdapterContractTests(() => myAdapter());
 * ```
 */
export function runAdapterContractTests(factory: AdapterFactory): void {
  describe('adapter contract', () => {
    let adapter: Adapter;

    beforeEach(async () => {
      adapter = await factory();
    });

    describe('users', () => {
      it('creates a user and finds it by id and by email', async () => {
        const input = userInput();
        const created = await adapter.createUser(input);

        expect(created).toEqual({
          ...input,
          createdAt: expect.any(Date) as Date,
          updatedAt: expect.any(Date) as Date,
        });
        expect(await adapter.findUserById(input.id)).toEqual(created);
        expect(await adapter.findUserByEmail(input.email)).toEqual(created);
      });

      it('allows a user without a password', async () => {
        const created = await adapter.createUser(userInput({ passwordHash: null }));
        expect(created.passwordHash).toBeNull();
      });

      it('returns null for unknown users', async () => {
        expect(await adapter.findUserById(randomUUID())).toBeNull();
        expect(await adapter.findUserByEmail('nobody@example.com')).toBeNull();
      });

      it('rejects a duplicate email with EMAIL_TAKEN', async () => {
        const email = 'taken@example.com';
        await adapter.createUser(userInput({ email }));

        const error: unknown = await adapter
          .createUser(userInput({ email }))
          .catch((e: unknown) => e);
        expect(isEmailTaken(error)).toBe(true);
      });

      it('lets exactly one of two concurrent sign-ups with the same email succeed', async () => {
        const email = 'race@example.com';
        const results = await Promise.allSettled([
          adapter.createUser(userInput({ email })),
          adapter.createUser(userInput({ email })),
        ]);

        const fulfilled = results.filter((r) => r.status === 'fulfilled');
        const rejected = results.filter((r) => r.status === 'rejected');
        expect(fulfilled).toHaveLength(1);
        expect(rejected).toHaveLength(1);
        expect(isEmailTaken(rejected[0]?.reason)).toBe(true);
      });

      it('updates fields, bumps updatedAt, and leaves id and createdAt alone', async () => {
        const created = await adapter.createUser(userInput());
        const updated = await adapter.updateUser(created.id, {
          passwordHash: 'new-hash',
          roles: ['admin'],
        });

        expect(updated).toMatchObject({
          id: created.id,
          email: created.email,
          passwordHash: 'new-hash',
          roles: ['admin'],
          createdAt: created.createdAt,
        });
        expect(updated?.updatedAt.getTime()).toBeGreaterThanOrEqual(created.updatedAt.getTime());
        expect(await adapter.findUserById(created.id)).toEqual(updated);
      });

      it('moves a user to a new email', async () => {
        const created = await adapter.createUser(userInput({ email: 'old@example.com' }));
        await adapter.updateUser(created.id, { email: 'new@example.com' });

        expect(await adapter.findUserByEmail('old@example.com')).toBeNull();
        expect((await adapter.findUserByEmail('new@example.com'))?.id).toBe(created.id);
      });

      it('rejects changing to an email another user has with EMAIL_TAKEN', async () => {
        await adapter.createUser(userInput({ email: 'a@example.com' }));
        const b = await adapter.createUser(userInput({ email: 'b@example.com' }));

        const error: unknown = await adapter
          .updateUser(b.id, { email: 'a@example.com' })
          .catch((e: unknown) => e);
        expect(isEmailTaken(error)).toBe(true);
        expect((await adapter.findUserById(b.id))?.email).toBe('b@example.com');
      });

      it('returns null when updating an unknown user', async () => {
        expect(await adapter.updateUser(randomUUID(), { roles: ['admin'] })).toBeNull();
      });

      it('never hands out references to stored users', async () => {
        const input = userInput({ roles: ['user'] });
        const created = await adapter.createUser(input);

        input.roles.push('mutated-input');
        created.roles.push('mutated-result');
        const found = await adapter.findUserById(created.id);
        found?.roles.push('mutated-find');

        expect((await adapter.findUserById(created.id))?.roles).toEqual(['user']);
      });
    });

    describe('refresh tokens', () => {
      async function createUserId(): Promise<string> {
        return (await adapter.createUser(userInput())).id;
      }

      it('creates a token and finds it by hash', async () => {
        const input = tokenInput(await createUserId());
        const created = await adapter.createRefreshToken(input);

        expect(created).toEqual({
          ...input,
          revokedAt: null,
          replacedById: null,
          createdAt: expect.any(Date) as Date,
        });
        expect(await adapter.findRefreshTokenByHash(input.tokenHash)).toEqual(created);
      });

      it('returns null for an unknown hash', async () => {
        expect(await adapter.findRefreshTokenByHash('unknown')).toBeNull();
      });

      it('revokes an active token exactly once, recording its replacement', async () => {
        const token = await adapter.createRefreshToken(tokenInput(await createUserId()));
        const replacedById = randomUUID();

        expect(await adapter.revokeRefreshToken(token.id, { replacedById })).toBe(true);
        expect(await adapter.revokeRefreshToken(token.id)).toBe(false);

        const stored = await adapter.findRefreshTokenByHash(token.tokenHash);
        expect(stored?.revokedAt).toBeInstanceOf(Date);
        expect(stored?.replacedById).toBe(replacedById);
      });

      it('lets exactly one of two concurrent revocations win', async () => {
        const token = await adapter.createRefreshToken(tokenInput(await createUserId()));
        const results = await Promise.all([
          adapter.revokeRefreshToken(token.id, { replacedById: randomUUID() }),
          adapter.revokeRefreshToken(token.id, { replacedById: randomUUID() }),
        ]);
        expect(results.filter(Boolean)).toHaveLength(1);
      });

      it('returns false when revoking an unknown token', async () => {
        expect(await adapter.revokeRefreshToken(randomUUID())).toBe(false);
      });

      it('revokes a whole family, and only that family', async () => {
        const userId = await createUserId();
        const familyId = randomUUID();
        const first = await adapter.createRefreshToken(tokenInput(userId, { familyId }));
        const second = await adapter.createRefreshToken(tokenInput(userId, { familyId }));
        const other = await adapter.createRefreshToken(tokenInput(userId));

        await adapter.revokeRefreshToken(first.id, { replacedById: second.id });
        const firstRevokedAt = (await adapter.findRefreshTokenByHash(first.tokenHash))?.revokedAt;

        await adapter.revokeFamily(familyId);

        const find = (hash: string) => adapter.findRefreshTokenByHash(hash);
        expect((await find(second.tokenHash))?.revokedAt).toBeInstanceOf(Date);
        expect((await find(first.tokenHash))?.revokedAt).toEqual(firstRevokedAt);
        expect((await find(other.tokenHash))?.revokedAt).toBeNull();
      });

      it('never hands out references to stored tokens', async () => {
        const token = await adapter.createRefreshToken(tokenInput(await createUserId()));
        token.revokedAt = new Date();

        expect((await adapter.findRefreshTokenByHash(token.tokenHash))?.revokedAt).toBeNull();
      });
    });
  });
}
