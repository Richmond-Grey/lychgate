import { describe, expect, it } from 'vitest';
import * as core from './index.js';

describe('@lychgate/core public API', () => {
  // Guards against accidentally exporting internals. Update deliberately when the API changes.
  it('exports exactly the intended runtime values', () => {
    expect(Object.keys(core).sort()).toEqual([
      'ARGON2ID_DEFAULTS',
      'EmailTakenError',
      'LychgateError',
      'PASSWORD_MAX_LENGTH',
      'PASSWORD_MIN_LENGTH',
      'PasswordPolicyError',
      'hashPassword',
      'isLychgateError',
      'memoryAdapter',
      'needsRehash',
      'normalizeEmail',
      'verifyPassword',
    ]);
  });
});
