import { describe, expect, it } from 'vitest';
import { normalizeEmail } from './email.js';

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
