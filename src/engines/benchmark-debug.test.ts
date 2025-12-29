/**
 * Debug test to check what's being imported from benchmark module
 */

import { describe, it, expect } from 'vitest';

describe('Benchmark Import Debug', () => {
  it('should import benchmark module', async () => {
    const benchmarkModule = await import('./benchmark');
    console.log('Benchmark module keys:', Object.keys(benchmarkModule));
    console.log('BenchmarkService:', benchmarkModule.BenchmarkService);
    console.log('BenchmarkService type:', typeof benchmarkModule.BenchmarkService);
    
    expect(benchmarkModule).toBeDefined();
    expect(benchmarkModule.BenchmarkService).toBeDefined();
    expect(typeof benchmarkModule.BenchmarkService).toBe('function');
  });
});