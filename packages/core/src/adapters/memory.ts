/* eslint-disable @typescript-eslint/require-await --
 * Methods are `async` on purpose even without `await`: it turns thrown errors into rejected
 * promises, which is what the Adapter interface promises callers. */
import type { Adapter } from '../adapter.js';
import { EmailTakenError } from '../errors.js';
import type { RefreshTokenRecord, User } from '../types.js';

/**
 * An adapter that keeps everything in memory. For tests, examples and local development.
 * All data is lost when the process exits.
 *
 * Every method copies data in and out, so callers can never mutate stored state by accident.
 */
export function memoryAdapter(): Adapter {
  const users = new Map<string, User>();
  const userIdByEmail = new Map<string, string>();
  const tokens = new Map<string, RefreshTokenRecord>();
  const tokenIdByHash = new Map<string, string>();
  const revokedFamilies = new Set<string>();

  const copy = <T>(value: T): T => structuredClone(value);
  const copyOrNull = <T>(value: T | undefined): T | null => (value ? copy(value) : null);

  return {
    async createUser(input) {
      // JavaScript is single-threaded and there is no `await` between this check and the
      // insert below, so two concurrent calls cannot both pass it. That is our "unique constraint".
      if (userIdByEmail.has(input.email)) throw new EmailTakenError();

      const now = new Date();
      const user: User = {
        id: input.id,
        email: input.email,
        passwordHash: input.passwordHash,
        roles: [...input.roles],
        createdAt: now,
        updatedAt: now,
      };
      users.set(user.id, user);
      userIdByEmail.set(user.email, user.id);
      return copy(user);
    },

    async findUserById(id) {
      return copyOrNull(users.get(id));
    },

    async findUserByEmail(email) {
      const id = userIdByEmail.get(email);
      return id === undefined ? null : copyOrNull(users.get(id));
    },

    async updateUser(id, input) {
      const existing = users.get(id);
      if (!existing) return null;

      const email = input.email ?? existing.email;
      const emailChanged = email !== existing.email;
      if (emailChanged && userIdByEmail.has(email)) throw new EmailTakenError();

      // Pick fields explicitly, so stray keys at runtime (e.g. `id`) cannot overwrite anything.
      const updated: User = {
        ...existing,
        email,
        passwordHash: input.passwordHash !== undefined ? input.passwordHash : existing.passwordHash,
        roles: input.roles ? [...input.roles] : existing.roles,
        updatedAt: new Date(),
      };
      if (emailChanged) {
        userIdByEmail.delete(existing.email);
        userIdByEmail.set(updated.email, id);
      }
      users.set(id, updated);
      return copy(updated);
    },

    async createRefreshToken(input) {
      const token: RefreshTokenRecord = {
        id: input.id,
        userId: input.userId,
        familyId: input.familyId,
        tokenHash: input.tokenHash,
        expiresAt: new Date(input.expiresAt),
        revokedAt: null,
        replacedById: null,
        createdAt: new Date(),
      };
      tokens.set(token.id, token);
      tokenIdByHash.set(token.tokenHash, token.id);
      return copy(token);
    },

    async findRefreshTokenByHash(tokenHash) {
      const id = tokenIdByHash.get(tokenHash);
      return id === undefined ? null : copyOrNull(tokens.get(id));
    },

    async revokeRefreshToken(id, input) {
      const token = tokens.get(id);
      // Compare-and-set: only an active token can be revoked, and only once.
      if (!token || token.revokedAt !== null) return false;
      token.revokedAt = new Date(input.revokedAt);
      token.replacedById = input.replacedById ?? null;
      return true;
    },

    async revokeFamily(familyId, revokedAt) {
      revokedFamilies.add(familyId);
      for (const token of tokens.values()) {
        if (token.familyId === familyId && token.revokedAt === null) {
          token.revokedAt = new Date(revokedAt);
        }
      }
    },

    async isFamilyRevoked(familyId) {
      return revokedFamilies.has(familyId);
    },
  };
}
