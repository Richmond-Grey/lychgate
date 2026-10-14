import type { Adapter } from './adapter.js';
import { parseDuration } from './duration.js';
import type { Duration } from './duration.js';
import { LychgateError } from './errors.js';
import { resolveHashOptions } from './password.js';
import type { HashOptions } from './password.js';

/** HS256 keys shorter than the hash output (32 bytes) weaken it (RFC 7518 §3.2). */
const SECRET_MIN_BYTES = 32;

const DEFAULT_ACCESS_TOKEN_TTL = '15m';
const DEFAULT_REFRESH_TOKEN_TTL = '30d';

export interface AuthConfig {
  adapter: Adapter;
  /**
   * Key for signing access tokens (HMAC-SHA256). At least 32 bytes. Load it from an environment
   * variable or secret manager, never from source code. Generate one with:
   * `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"`
   */
  secret: string | Uint8Array;
  /** Who issues the tokens (the `iss` claim), e.g. `"https://api.example.com"`. */
  issuer: string;
  /** Who the tokens are for (the `aud` claim), e.g. `"example-api"`. */
  audience: string;
  /** How long an access token is valid. Default `"15m"`. Keep it short: they can't be revoked. */
  accessTokenTtl?: Duration;
  /** How long a refresh token is valid. Each refresh issues a new one, so this is an idle timeout. Default `"30d"`. */
  refreshTokenTtl?: Duration;
  /** See `rejectRevokedRefreshToken` in auth.ts for the trade-off. Default `0` (strict). */
  refreshReuseLeewaySeconds?: number;
  /** argon2id cost. Defaults to OWASP's recommendation. Raising it upgrades hashes on next login. */
  passwordHashing?: HashOptions;
  /** The clock. Injectable so tests never depend on real time. Default `() => new Date()`. */
  now?: () => Date;
}

export interface ResolvedAuthConfig {
  adapter: Adapter;
  secret: Uint8Array;
  issuer: string;
  audience: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  refreshReuseLeewaySeconds: number;
  passwordHashing: Required<HashOptions>;
  now: () => Date;
}

/**
 * Validates the config once, at startup, so mistakes fail loudly at boot rather than on the
 * first request. Throws `INVALID_CONFIG` (or `INVALID_HASH_OPTIONS`). Messages name the bad
 * option but never echo its value, since it may be the secret.
 */
export function resolveAuthConfig(config: AuthConfig): ResolvedAuthConfig {
  // Validators take `unknown`: plain-JavaScript callers get the same protection as TypeScript ones.
  const raw = config as unknown;
  if (typeof raw !== 'object' || raw === null)
    throw invalidConfig('createAuth() needs a config object.');

  const {
    adapter,
    secret,
    issuer,
    audience,
    accessTokenTtl = DEFAULT_ACCESS_TOKEN_TTL,
    refreshTokenTtl = DEFAULT_REFRESH_TOKEN_TTL,
    refreshReuseLeewaySeconds = 0,
    passwordHashing,
    now = () => new Date(),
  } = raw as Partial<Record<keyof AuthConfig, unknown>>;

  return {
    adapter: requireAdapter(adapter),
    secret: requireSecret(secret),
    issuer: requireNonEmptyString(issuer, 'issuer'),
    audience: requireNonEmptyString(audience, 'audience'),
    accessTokenTtlSeconds: requireDuration(accessTokenTtl, 'accessTokenTtl'),
    refreshTokenTtlSeconds: requireDuration(refreshTokenTtl, 'refreshTokenTtl'),
    refreshReuseLeewaySeconds: requireLeeway(refreshReuseLeewaySeconds),
    passwordHashing: resolveHashOptions(passwordHashing as HashOptions | undefined),
    now: requireClock(now),
  };
}

function requireAdapter(value: unknown): Adapter {
  if (typeof value !== 'object' || value === null) throw invalidConfig('`adapter` is required.');
  return value as Adapter;
}

function requireSecret(value: unknown): Uint8Array {
  let bytes: Uint8Array | null = null;
  if (typeof value === 'string') bytes = new TextEncoder().encode(value);
  // Copy, so later changes to the caller's buffer can't change our key.
  else if (value instanceof Uint8Array) bytes = Uint8Array.from(value);

  if (!bytes || bytes.byteLength < SECRET_MIN_BYTES) {
    throw invalidConfig(
      `\`secret\` must be a string or Uint8Array of at least ${String(SECRET_MIN_BYTES)} bytes.`,
    );
  }
  return bytes;
}

function requireNonEmptyString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw invalidConfig(`\`${name}\` must be a non-empty string.`);
  }
  return value;
}

function requireDuration(value: unknown, name: string): number {
  const seconds = parseDuration(value);
  if (seconds === null) {
    throw invalidConfig(
      `\`${name}\` must be a positive whole number of seconds or a string like "15m", "12h" or "30d".`,
    );
  }
  return seconds;
}

function requireLeeway(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw invalidConfig('`refreshReuseLeewaySeconds` must be a number of seconds, 0 or more.');
  }
  return value;
}

function requireClock(value: unknown): () => Date {
  if (typeof value !== 'function')
    throw invalidConfig('`now` must be a function returning a Date.');
  return value as () => Date;
}

function invalidConfig(message: string): LychgateError {
  return new LychgateError('INVALID_CONFIG', message);
}
