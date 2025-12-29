import { describe, it, expect } from 'vitest';
import { BenchmarkService } from './benchmark-minimal';

describe('Minimal Benchmark Test', () => {
  it('should import BenchmarkService', () => {
    expect(BenchmarkService).toBeDefined();
    expect(typeof BenchmarkService).toBe('function');
  });
});