/**
 * @lychgate/core
 *
 * Framework- and storage-agnostic authentication core. Everything exported here is public API.
 */

export type { RefreshTokenRecord, User } from './types.js';
export type {
  Adapter,
  CreateRefreshTokenInput,
  CreateUserInput,
  RevokeRefreshTokenOptions,
  UpdateUserInput,
} from './adapter.js';
export { memoryAdapter } from './adapters/memory.js';

export {
  ARGON2ID_DEFAULTS,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  hashPassword,
  needsRehash,
  verifyPassword,
} from './password.js';
export type { HashOptions } from './password.js';

export { normalizeEmail } from './email.js';

export { EmailTakenError, LychgateError, PasswordPolicyError, isLychgateError } from './errors.js';
export type { LychgateErrorCode, PasswordPolicyViolation } from './errors.js';
