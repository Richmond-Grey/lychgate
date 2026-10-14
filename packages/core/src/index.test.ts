import { describe, expect, it } from 'vitest';
import { VERSION } from './index.js';

describe('@lychgate/core', () => {
  it('exports a version that matches package.json', async () => {
    const pkg = (await import('../package.json', { with: { type: 'json' } })) as {
      default: { version: string };
    };
    expect(VERSION).toBe(pkg.default.version);
  });
});
