/*
 * IDs are plain strings (UUIDs from crypto.randomUUID()), not branded types. IDs arrive from
 * databases, JWT `sub` claims and cookies, so a brand would need a cast at every boundary and
 * would suggest a validation that never happened. Mixing up IDs is guarded against by keeping
 * the adapter API small and using descriptive parameter names instead.
 *
 * Optional fields are `T | null` rather than `field?: T`, so every key is always present.
 * That maps one-to-one onto SQL NULL and avoids "missing vs undefined" ambiguity.
 */

export interface User {
  id: string;
  /** Always stored normalized (trimmed and lowercased). See `normalizeEmail`. */
  email: string;
  /** argon2id PHC string. `null` for users without a password (e.g. OAuth-only accounts). */
  passwordHash: string | null;
  roles: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface RefreshTokenRecord {
  id: string;
  userId: string;
  /** Every token created by rotating the same login shares a family. Reuse revokes the family. */
  familyId: string;
  /** A hash of the opaque token. The raw token itself is never stored. */
  tokenHash: string;
  expiresAt: Date;
  /** Set when the token is rotated or revoked. A token with `revokedAt` set must never be accepted. */
  revokedAt: Date | null;
  /** When this token was rotated, the ID of the token that replaced it. */
  replacedById: string | null;
  createdAt: Date;
}
