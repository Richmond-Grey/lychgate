import { describe, expect, it } from 'vitest';
import { parseDuration } from './duration.js';

describe('parseDuration', () => {
  it.each([
    [30, 30],
    ['45s', 45],
    ['15m', 900],
    ['12h', 43_200],
    ['30d', 2_592_000],
  ])('parses %j as %d seconds', (input, seconds) => {
    expect(parseDuration(input)).toBe(seconds);
  });

  it.each([
    0,
    -1,
    1.5,
    Number.NaN,
    Infinity,
    '',
    '15',
    '0m',
    '-5m',
    '1.5h',
    '15 m',
    '2w',
    '15M',
    null,
    {},
  ])('rejects %j', (input) => {
    expect(parseDuration(input)).toBeNull();
  });
});
