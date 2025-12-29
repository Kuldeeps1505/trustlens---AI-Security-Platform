import { describe, it, expect } from 'vitest';

describe('Import Test', () => {
  it('should import all dependencies', async () => {
    const module = await import('./benchmark-import-test');
    console.log('Module keys:', Object.keys(module));
    expect(module.testExport).toBe('working');
  });
});