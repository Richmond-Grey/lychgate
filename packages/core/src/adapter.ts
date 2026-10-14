import type { RefreshTokenRecord, User } from './types.js';

/*
 * Lychgate core generates record IDs (crypto.randomUUID()) and passes them in, so every adapter
 * produces the same ID format and core can know a token's ID before it is stored (needed to
 * rotate atomically). Adapters set the timestamps (`createdAt`, `updatedAt`).
 */

export interface CreateUserInput {
  id: string;
  /** Already normalized by core. Adapters treat it as an exact-match key. */
  email: string;
  passwordHash: string | null;
  roles: string[];
}

export type UpdateUserInput = Partial<Pick<User, 'email' | 'passwordHash' | 'roles'>>;

export interface CreateRefreshTokenInput {
  id: string;
  userId: string;
  familyId: string;
  tokenHash: string;
  expiresAt: Date;
}

export interface RevokeRefreshTokenOptions {
  /** Set when revoking because of rotation: the ID of the replacement token. */
  replacedById?: string;
}

/**
 * Storage interface. Implement this to plug Lychgate into any database.
 * The behaviour is pinned down by `runAdapterContractTests` from `@lychgate/core/testing`.
 * Every adapter should pass that suite.
 *
 * All methods must return fresh objects, never references to internal state.
 */
export interface Adapter {
  /**
   * Must reject with `EmailTakenError` if the email exists. This must be enforced by the
   * store itself (e.g. a unique constraint), not by a lookup beforehand, so that two
   * concurrent sign-ups with the same email cannot both succeed.
   */
  createUser(input: CreateUserInput): Promise<User>;
  findUserById(id: string): Promise<User | null>;
  findUserByEmail(email: string): Promise<User | null>;
  /**
   * Applies the given fields and bumps `updatedAt`. Resolves to `null` if no user has that ID.
   * Rejects with `EmailTakenError` if changing the email would create a duplicate.
   */
  updateUser(id: string, input: UpdateUserInput): Promise<User | null>;

  createRefreshToken(input: CreateRefreshTokenInput): Promise<RefreshTokenRecord>;
  findRefreshTokenByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  /**
   * Atomically revokes a token that is still active, i.e. a compare-and-set on `revokedAt IS NULL`.
   * Resolves to `true` only for the call that actually revoked it. Resolves to `false` if the
   * token was already revoked or does not exist.
   *
   * This is what makes rotation race-safe: if two requests present the same refresh token at
   * the same time, only one of them wins. The other is treated as reuse.
   */
  revokeRefreshToken(id: string, options?: RevokeRefreshTokenOptions): Promise<boolean>;
  /** Revokes every still-active token in the family. Already-revoked tokens keep their `revokedAt`. */
  revokeFamily(familyId: string): Promise<void>;
}
