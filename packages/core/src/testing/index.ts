/**
 * @lychgate/core/testing
 *
 * Test helpers for adapter authors. Kept out of the main entry point so that `vitest` is only
 * needed by code that imports this path.
 */
export { runAdapterContractTests } from './contract.js';
export type { AdapterFactory } from './contract.js';
