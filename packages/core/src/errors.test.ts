import { describe, expect, it } from 'vitest';
import { EmailTakenError, LychgateError, PasswordPolicyError, isLychgateError } from './errors.js';

describe('errors', () => {
  it('gives every error a stable code and a name', () => {
    const emailTaken = new EmailTakenError();
    expect(emailTaken).toBeInstanceOf(LychgateError);
    expect(emailTaken.code).toBe('EMAIL_TAKEN');
    expect(emailTaken.name).toBe('EmailTakenError');

    const policy = new PasswordPolicyError('TOO_SHORT', 'too short');
    expect(policy.code).toBe('INVALID_PASSWORD_POLICY');
    expect(policy.reason).toBe('TOO_SHORT');
  });

  it('isLychgateError recognises Lychgate errors and narrows by code', () => {
    const error = new EmailTakenError();
    expect(isLychgateError(error)).toBe(true);
    expect(isLychgateError(error, 'EMAIL_TAKEN')).toBe(true);
    expect(isLychgateError(error, 'INVALID_PASSWORD_POLICY')).toBe(false);
  });

  it('isLychgateError rejects look-alikes and non-errors', () => {
    expect(isLychgateError(Object.assign(new Error('x'), { code: 'EMAIL_TAKEN' }))).toBe(false);
    expect(isLychgateError(null)).toBe(false);
    expect(isLychgateError('EMAIL_TAKEN')).toBe(false);
  });

  it('isLychgateError works across separate copies of the module (ESM + CJS)', () => {
    // Simulates an error thrown by another copy of the class: same global brand, different class.
    const fromOtherCopy = { code: 'EMAIL_TAKEN', [Symbol.for('lychgate.error')]: true };
    expect(isLychgateError(fromOtherCopy, 'EMAIL_TAKEN')).toBe(true);
  });
});
