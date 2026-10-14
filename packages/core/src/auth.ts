import { randomBytes, randomUUID } from 'node:crypto';
import { resolveAuthConfig } from './config.js';
import type { AuthConfig } from './config.js';
import { normalizeEmail, parseEmail } from './email.js';
import { LychgateError } from './errors.js';
import { hashPassword, needsRehash, rehashPassword, verifyPassword } from './password.js';
import { signAccessToken, verifyAccessToken } from './tokens/access-token.js';
import type { AccessTokenClaims, AccessTokenSettings } from './tokens/access-token.js';
import {
  REFRESH_TOKEN_MAX_LENGTH,
  generateRefreshToken,
  hashRefreshToken,
} from './tokens/refresh-token.js';
import type { RefreshTokenRecord, User } from './types.js';

export interface Credentials {
  email: string;
  password: string;
}

/** A user as returned to callers: everything except the password hash. */
export type PublicUser = Omit<User, 'passwordHash'>;

export interface AuthSession {
  user: PublicUser;
  accessToken: string;
  /** When `accessToken` expires. Refresh shortly before this. */
  expiresAt: Date;
  /** Opaque. Returned exactly once: Lychgate only stores its hash and can't show it again. */
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

export interface Auth {
  /**
   * Creates a user with no roles. Throws `INVALID_EMAIL`, `INVALID_PASSWORD_POLICY` or
   * `EMAIL_TAKEN`. Does not log the user in.
   *
   * Note: `EMAIL_TAKEN` tells the caller that an address is registered. That's inherent to a
   * sign-up form that reports duplicates; hiding it needs email verification (planned for v2).
   */
  register(credentials: Credentials): Promise<PublicUser>;
  /** Starts a new session. Throws `INVALID_CREDENTIALS` for any failure, whatever the cause. */
  login(credentials: Credentials): Promise<AuthSession>;
  /**
   * Exchanges a refresh token for a new session, rotating the refresh token. Throws
   * `INVALID_REFRESH_TOKEN`, `REFRESH_TOKEN_EXPIRED` or `REFRESH_TOKEN_REUSED`.
   */
  refresh(refreshToken: string): Promise<AuthSession>;
  /** Ends the session (the whole token family). Never throws for unknown or already-revoked tokens. */
  logout(refreshToken: string): Promise<void>;
  /**
   * Checks an access token's signature and claims, without touching storage. Throws
   * `INVALID_ACCESS_TOKEN` or `ACCESS_TOKEN_EXPIRED`.
   */
  verifyAccessToken(accessToken: string): Promise<AccessTokenClaims>;
}

export function createAuth(config: AuthConfig): Auth {
  const settings = resolveAuthConfig(config);
  const { adapter } = settings;
  const accessTokenSettings: AccessTokenSettings = {
    secret: settings.secret,
    issuer: settings.issuer,
    audience: settings.audience,
    ttlSeconds: settings.accessTokenTtlSeconds,
  };

  let dummyHash: Promise<string> | undefined;
  /**
   * A hash of a random password nobody knows, made with the same parameters as real hashes.
   * Login verifies against it when there's no real hash, so that case costs the same as a
   * wrong password. Created on first use, so `createAuth` itself stays instant.
   */
  function getDummyHash(): Promise<string> {
    dummyHash ??= hashPassword(randomBytes(32).toString('base64url'), settings.passwordHashing);
    return dummyHash;
  }

  async function startSession(
    user: User,
    familyId: string,
    refreshTokenId: string,
    now: Date,
  ): Promise<AuthSession> {
    const refreshToken = generateRefreshToken();
    const refreshTokenExpiresAt = new Date(now.getTime() + settings.refreshTokenTtlSeconds * 1000);
    await adapter.createRefreshToken({
      id: refreshTokenId,
      userId: user.id,
      familyId,
      tokenHash: hashRefreshToken(refreshToken),
      expiresAt: refreshTokenExpiresAt,
    });
    const access = await signAccessToken(accessTokenSettings, user, now);

    return {
      user: toPublicUser(user),
      accessToken: access.token,
      expiresAt: access.expiresAt,
      refreshToken,
      refreshTokenExpiresAt,
    };
  }

  async function findRefreshToken(refreshToken: unknown): Promise<RefreshTokenRecord | null> {
    if (
      typeof refreshToken !== 'string' ||
      refreshToken === '' ||
      refreshToken.length > REFRESH_TOKEN_MAX_LENGTH
    ) {
      return null;
    }
    return adapter.findRefreshTokenByHash(hashRefreshToken(refreshToken));
  }

  /**
   * Someone presented a refresh token that has already been revoked (or whose family has).
   *
   * Normally that means the token was copied: the real client and an attacker both hold it,
   * and one of them has already rotated it. We can't tell which one is asking now, so we
   * revoke the whole family. Every holder, including the attacker, must log in again.
   *
   * The leeway is for a harmless version of the same thing: two browser tabs (or a retry after
   * a dropped response) refreshing with the same token at almost the same moment. One wins,
   * and the other would trip reuse detection and log the user out. Within the leeway, a token
   * that was *rotated* (it has a replacement) is just rejected, without revoking the family,
   * and the client should retry with the newer token the winning request received.
   *
   * The cost: a thief replaying a stolen token inside that window goes undetected (though they
   * get nothing back). That's why the default leeway is 0, meaning always strict. Tokens revoked
   * by logout or a family revocation have no replacement, so they never get the leeway.
   */
  async function rejectRevokedRefreshToken(token: RefreshTokenRecord, now: Date): Promise<never> {
    if (token.revokedAt !== null && token.replacedById !== null) {
      const elapsedMs = now.getTime() - token.revokedAt.getTime();
      if (elapsedMs >= 0 && elapsedMs < settings.refreshReuseLeewaySeconds * 1000) {
        throw invalidRefreshToken();
      }
    }
    await adapter.revokeFamily(token.familyId, now);
    throw new LychgateError(
      'REFRESH_TOKEN_REUSED',
      'Refresh token was already used. The session has been revoked; log in again.',
    );
  }

  return {
    async register(credentials) {
      const { email, password } = readCredentials(credentials);
      const normalizedEmail = parseEmail(email);
      // Hash before creating: hashPassword enforces the password policy.
      const passwordHash = await hashPassword(password as string, settings.passwordHashing);
      // No "does this email exist?" lookup first: createUser enforces uniqueness atomically.
      const user = await adapter.createUser({
        id: randomUUID(),
        email: normalizedEmail,
        passwordHash,
        roles: [],
      });
      return toPublicUser(user);
    },

    async login(credentials) {
      const now = settings.now();
      const { email, password } = readCredentials(credentials);
      const user =
        typeof email === 'string' ? await adapter.findUserByEmail(normalizeEmail(email)) : null;

      // Always do exactly one full argon2 verification, even with no user or no password,
      // so response time doesn't reveal whether an email is registered.
      const hash = user?.passwordHash ?? (await getDummyHash());
      const plain = typeof password === 'string' ? password : '';
      const passwordMatches = await verifyPassword(hash, plain);

      if (!user || user.passwordHash === null || !passwordMatches) {
        throw new LychgateError('INVALID_CREDENTIALS', 'Invalid email or password.');
      }

      // This is the only moment we have the plaintext, so upgrade outdated hashes now.
      let current = user;
      if (needsRehash(user.passwordHash, settings.passwordHashing)) {
        const passwordHash = await rehashPassword(plain, settings.passwordHashing);
        current = (await adapter.updateUser(user.id, { passwordHash })) ?? user;
      }

      return startSession(current, randomUUID(), randomUUID(), now);
    },

    async refresh(refreshToken) {
      const now = settings.now();
      const token = await findRefreshToken(refreshToken);
      if (!token) throw invalidRefreshToken();
      // The family check catches a token that was created by a concurrent refresh just after
      // its family was revoked (see `Adapter.isFamilyRevoked`).
      if (token.revokedAt !== null || (await adapter.isFamilyRevoked(token.familyId))) {
        return rejectRevokedRefreshToken(token, now);
      }
      if (token.expiresAt.getTime() <= now.getTime()) {
        throw new LychgateError('REFRESH_TOKEN_EXPIRED', 'Refresh token has expired.');
      }

      const user = await adapter.findUserById(token.userId);
      if (!user) {
        await adapter.revokeFamily(token.familyId, now);
        throw invalidRefreshToken();
      }

      // Rotate: revoke the old token FIRST, then issue the new one. The revoke is an atomic
      // compare-and-set, so exactly one concurrent caller wins. If the process dies between
      // the two steps, the user just has to log in again. At no point are two tokens valid.
      const newTokenId = randomUUID();
      const won = await adapter.revokeRefreshToken(token.id, {
        revokedAt: now,
        replacedById: newTokenId,
      });
      if (!won) {
        // Revoked between our read and our write: a concurrent refresh or a logout.
        const latest = await adapter.findRefreshTokenByHash(token.tokenHash);
        if (latest?.revokedAt == null) throw invalidRefreshToken();
        return rejectRevokedRefreshToken(latest, now);
      }

      return startSession(user, token.familyId, newTokenId, now);
    },

    async logout(refreshToken) {
      const token = await findRefreshToken(refreshToken);
      if (token) await adapter.revokeFamily(token.familyId, settings.now());
    },

    verifyAccessToken(accessToken) {
      return verifyAccessToken(accessTokenSettings, accessToken, settings.now());
    },
  };
}

/** Request bodies are untrusted: read the two fields without assuming their types. */
function readCredentials(input: unknown): { email: unknown; password: unknown } {
  if (typeof input !== 'object' || input === null) return { email: undefined, password: undefined };
  const { email, password } = input as Record<string, unknown>;
  return { email, password };
}

/** An explicit allowlist, so a field added to User later can't leak by accident. */
function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    email: user.email,
    roles: [...user.roles],
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function invalidRefreshToken(): LychgateError {
  return new LychgateError('INVALID_REFRESH_TOKEN', 'Refresh token is invalid.');
}
