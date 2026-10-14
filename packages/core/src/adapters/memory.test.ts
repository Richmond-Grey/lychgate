import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { runAdapterContractTests } from '../testing/index.js';
import { memoryAdapter } from './memory.js';

describe('memoryAdapter', () => {
  runAdapterContractTests(() => memoryAdapter());

  it('keeps separate instances isolated', async () => {
    const a = memoryAdapter();
    const b = memoryAdapter();
    const user = await a.createUser({
      id: randomUUID(),
      email: 'only-in-a@example.com',
      passwordHash: null,
      roles: [],
    });

    expect(await b.findUserById(user.id)).toBeNull();
  });
});
