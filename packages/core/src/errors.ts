/**
 * Every error Lychgate throws on purpose carries a stable `code`.
 * Match on the code, never on the message: messages are for humans and may change.
 */
export type LychgateErrorCode =
  // Configuration (programmer errors, thrown at startup)
  | 'INVALID_CONFIG'
  | 'INVALID_HASH_OPTIONS'
  // Registration
  | 'INVALID_EMAIL'
  | 'INVALID_PASSWORD_POLICY'
  | 'EMAIL_TAKEN'
  // Login
  | 'INVALID_CREDENTIALS'
  // Tokens
  | 'INVALID_ACCESS_TOKEN'
  | 'ACCESS_TOKEN_EXPIRED'
  | 'INVALID_REFRESH_TOKEN'
  | 'REFRESH_TOKEN_EXPIRED'
  | 'REFRESH_TOKEN_REUSED';

// A global symbol (Symbol.for) is shared across module copies. If an app ends up loading both the
// ESM and CJS builds of this package, `instanceof` fails across them, but this brand still matches.
const LYCHGATE_ERROR = Symbol.for('lychgate.error');

export class LychgateError extends Error {
  readonly code: LychgateErrorCode;
  readonly [LYCHGATE_ERROR] = true;

  constructor(code: LychgateErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LychgateError';
    this.code = code;
  }
}

/** Thrown by an adapter when creating or updating a user would duplicate an email. */
export class EmailTakenError extends LychgateError {
  constructor() {
    // Deliberately does not echo the email back: errors end up in logs.
    super('EMAIL_TAKEN', 'A user with this email already exists.');
    this.name = 'EmailTakenError';
  }
}

export type PasswordPolicyViolation = 'NOT_A_STRING' | 'TOO_SHORT' | 'TOO_LONG';

/** Thrown when a new password fails the length policy. Never contains the password itself. */
export class PasswordPolicyError extends LychgateError {
  readonly reason: PasswordPolicyViolation;

  constructor(reason: PasswordPolicyViolation, message: string) {
    super('INVALID_PASSWORD_POLICY', message);
    this.name = 'PasswordPolicyError';
    this.reason = reason;
  }
}

/**
 * Type guard for Lychgate errors, optionally narrowed to one code.
 * Prefer this over `instanceof` (see the note on LYCHGATE_ERROR above).
 */
export function isLychgateError(error: unknown, code?: LychgateErrorCode): error is LychgateError {
  if (typeof error !== 'object' || error === null) return false;
  if ((error as Partial<Record<typeof LYCHGATE_ERROR, unknown>>)[LYCHGATE_ERROR] !== true) {
    return false;
  }
  return code === undefined || (error as LychgateError).code === code;
}
