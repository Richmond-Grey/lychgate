import { describe, expect, it } from 'vitest';
import { EMAIL_MAX_LENGTH, normalizeEmail, parseEmail } from './email.js';

describe('normalizeEmail', () => {
  it.each([
    ['Alice@Example.COM', 'alice@example.com'],
    ['  bob@example.com\t\n', 'bob@example.com'],
    ['  MiXeD@Case.Org ', 'mixed@case.org'],
    ['already@normal.io', 'already@normal.io'],
  ])('normalizes %j to %j', (input, expected) => {
    expect(normalizeEmail(input)).toBe(expected);
  });

  it('is idempotent', () => {
    const once = normalizeEmail('  Carol@Example.com ');
    expect(normalizeEmail(once)).toBe(once);
  });
});

// Invalid formats are covered end to end in auth.test.ts (register).
describe('parseEmail', () => {
  it('returns the normalized email', () => {
    expect(parseEmail('  Dave@Example.com ')).toBe('dave@example.com');
  });

  it(`accepts exactly ${String(EMAIL_MAX_LENGTH)} characters and rejects one more`, () => {
    const atLimit = `${'a'.repeat(EMAIL_MAX_LENGTH - '@x.io'.length)}@x.io`;
    expect(parseEmail(atLimit)).toBe(atLimit);
    expect(() => parseEmail(`a${atLimit}`)).toThrow(
      expect.objectContaining({ code: 'INVALID_EMAIL' }) as Error,
    );
  });
});
