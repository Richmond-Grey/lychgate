import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Each package is its own Vitest project, so `pnpm test` at the root runs them all.
    projects: ['packages/*'],
  },
});
