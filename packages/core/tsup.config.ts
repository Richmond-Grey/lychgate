import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { index: 'src/index.ts', 'testing/index': 'src/testing/index.ts' },
  format: ['esm', 'cjs'],
  // tsup's declaration build sets `baseUrl` internally, which TS 6 deprecates.
  // Scoped here so our own tsconfig doesn't need to ignore deprecations.
  dts: { compilerOptions: { ignoreDeprecations: '6.0' } },
  sourcemap: true,
  clean: true,
  target: 'node22',
});
