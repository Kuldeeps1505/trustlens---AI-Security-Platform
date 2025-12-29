import { describe, it, expect } from 'vitest';
import { SimpleBenchmarkService } from './benchmark-simple';

describe('Simple Benchmark Test', () => {
  it('should work', () => {
    const service = new SimpleBenchmarkService();
    expect(service.test()).toBe('working');
  });
});