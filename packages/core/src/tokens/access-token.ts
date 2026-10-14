import { randomUUID } from 'node:crypto';
import { SignJWT, errors, jwtVerify } from 'jose';
import type { JWTPayload } from 'jose';
import { LychgateError } from '../errors.js';

/** The only algorithm we sign with and the only one we accept. Pinning it blocks `alg: none`
 * and algorithm-confusion attacks, where a token claims a different algorithm than we use. */
const ALGORITHM = 'HS256';
/** Marks the JWT as an access token (RFC 9068), so a JWT made for another purpose with the
 * same key can't be passed off as one. */
const TOKEN_TYPE = 'at+jwt';
/** Allowance for small clock differences between servers when checking `exp`. */
const CLOCK_TOLERANCE_SECONDS = 5;

export interface AccessTokenSettings {
  secret: Uint8Array;
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

/**
 * What a verified access token tells you.
 *
 * `roles` is a snapshot from when the token was issued. Role changes take effect when the
 * client next refreshes (or the access token expires), not instantly. Keep the access token
 * TTL short for that reason.
 */
export interface AccessTokenClaims {
  userId: string;
  roles: string[];
  /** Unique ID of this token (`jti`). */
  tokenId: string;
  issuedAt: Date;
  expiresAt: Date;
}

const toEpochSeconds = (date: Date) => Math.floor(date.getTime() / 1000);

export async function signAccessToken(
  settings: AccessTokenSettings,
  user: { id: string; roles: string[] },
  now: Date,
): Promise<{ token: string; expiresAt: Date }> {
  const issuedAt = toEpochSeconds(now);
  const expiresAt = issuedAt + settings.ttlSeconds;

  const token = await new SignJWT({ roles: user.roles })
    .setProtectedHeader({ alg: ALGORITHM, typ: TOKEN_TYPE })
    .setSubject(user.id)
    .setIssuer(settings.issuer)
    .setAudience(settings.audience)
    .setIssuedAt(issuedAt)
    .setExpirationTime(expiresAt)
    .setJti(randomUUID())
    .sign(settings.secret);

  return { token, expiresAt: new Date(expiresAt * 1000) };
}

export async function verifyAccessToken(
  settings: AccessTokenSettings,
  token: unknown,
  now: Date,
): Promise<AccessTokenClaims> {
  if (typeof token !== 'string') throw invalidAccessToken();

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(token, settings.secret, {
      algorithms: [ALGORITHM],
      typ: TOKEN_TYPE,
      issuer: settings.issuer,
      audience: settings.audience,
      requiredClaims: ['sub', 'jti', 'iat', 'exp'],
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      currentDate: now,
    }));
  } catch (error) {
    // jose checks the signature before the claims, so "expired" always means "genuine but old".
    if (error instanceof errors.JWTExpired) {
      throw new LychgateError('ACCESS_TOKEN_EXPIRED', 'Access token has expired.');
    }
    // Nothing from jose's error is passed on: it can carry the token's claims.
    throw invalidAccessToken();
  }

  // The signature proves we issued it, but check the shape anyway rather than trusting a cast.
  const { sub, jti, iat, exp, roles } = payload;
  if (
    typeof sub !== 'string' ||
    typeof jti !== 'string' ||
    typeof iat !== 'number' ||
    typeof exp !== 'number' ||
    !isStringArray(roles)
  ) {
    throw invalidAccessToken();
  }

  return {
    userId: sub,
    roles,
    tokenId: jti,
    issuedAt: new Date(iat * 1000),
    expiresAt: new Date(exp * 1000),
  };
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function invalidAccessToken(): LychgateError {
  return new LychgateError('INVALID_ACCESS_TOKEN', 'Access token is invalid.');
}
