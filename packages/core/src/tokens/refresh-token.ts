import { createHash, randomBytes } from 'node:crypto';

const REFRESH_TOKEN_BYTES = 32;

/**
 * Upper bound on what we bother hashing. Real tokens are 43 characters (32 bytes as base64url).
 * Anything far longer is garbage and is rejected before any work is done.
 */
export const REFRESH_TOKEN_MAX_LENGTH = 256;

/** A new opaque refresh token: 256 random bits, base64url-encoded. Returned to the client once. */
export function generateRefreshToken(): string {
  return randomBytes(REFRESH_TOKEN_BYTES).toString('base64url');
}

/**
 * What we store instead of the token. A fast hash (SHA-256) is correct here, unlike for
 * passwords: the token has 256 bits of randomness, so there is nothing to brute-force, and a
 * deterministic hash lets us look the token up directly. A database leak reveals only hashes,
 * which cannot be presented as tokens.
 */
export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
