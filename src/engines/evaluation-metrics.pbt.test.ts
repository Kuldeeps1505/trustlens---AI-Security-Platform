/**
 * Property-based tests for Evaluation Metrics System
 * **Feature: trustlens-ai-security-platform, Property 24: Evaluation metric completeness**
 * **Validates: Requirements 7.2**
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { EvaluationMetricsCalculator, EvaluationMetrics } from './evaluation-metrics';
import { AttackResult, FirewallResponse } from '../types/core';
import { firewallResponseArb } from '../test-utils/generators';
import { v4 as uuidv4 } from 'uuid';

describe('Evaluation Metrics Property Tests', () => {
  const calculator = new EvaluationMetricsCalculator();

  /**
   * **Feature: trustlens-ai-security-platform, Property 24: Evaluation metric completeness**
   * *For any* completed evaluation, results should include block rate, false positive rate, and bypass rate metrics
   * **Validates: Requirements 7.2**
   */
  it('should always include required metrics in evaluation results', () => {
    fc.assert(
      fc.property(
        fc.array(firewallResponseArb, { minLength: 1, maxLength: 100 }),
        fc.option(fc.array(firewallResponseArb, { minLength: 0, maxLength: 50 })),
        (attackResponses, legitimateResponses) => {
          // Convert firewall responses to attack results
          const attackResults: AttackResult[] = attackResponses.map(response => ({
            attackId: uuidv4(),
            success: response.decision === 'ALLOW',
            firewallResponse: response,
            timestamp: new Date(),
            metrics: {
              processingTime: response.processingTime,
              confidence: response.attackCategory.confidence
            }
          }));

          const legitimateResults: AttackResult[] | undefined = legitimateResponses?.map(response => ({
            attackId: uuidv4(),
            success: response.decision === 'ALLOW',
            firewallResponse: response,
            timestamp: new Date(),
            metrics: {
              processingTime: response.processingTime,
              confidence: response.attackCategory.confidence
            }
          }));

          // Calculate metrics
          const metrics = calculator.calculateMetrics(attackResults, legitimateResults);

          // Property: All required metrics must be present and valid
          expect(metrics).toBeDefined();
          expect(typeof metrics.blockRate).toBe('number');
          expect(typeof metrics.falsePositiveRate).toBe('number');
          expect(typeof metrics.bypassRate).toBe('number');

          // Property: Metrics must be within valid ranges
          expect(metrics.blockRate).toBeGreaterThanOrEqual(0);
          expect(metrics.blockRate).toBeLessThanOrEqual(100);
          expect(metrics.falsePositiveRate).toBeGreaterThanOrEqual(0);
          expect(metrics.falsePositiveRate).toBeLessThanOrEqual(100);
          expect(metrics.bypassRate).toBeGreaterThanOrEqual(0);
          expect(metrics.bypassRate).toBeLessThanOrEqual(100);

          // Property: Additional required metrics must be present
          expect(typeof metrics.averageProcessingTime).toBe('number');
          expect(typeof metrics.averageRiskScore).toBe('number');
          expect(typeof metrics.totalRequests).toBe('number');
          expect(typeof metrics.blockedRequests).toBe('number');
          expect(typeof metrics.flaggedRequests).toBe('number');
          expect(typeof metrics.allowedRequests).toBe('number');

          // Property: Counts must be non-negative integers
          expect(metrics.totalRequests).toBeGreaterThanOrEqual(0);
          expect(metrics.blockedRequests).toBeGreaterThanOrEqual(0);
          expect(metrics.flaggedRequests).toBeGreaterThanOrEqual(0);
          expect(metrics.allowedRequests).toBeGreaterThanOrEqual(0);

          // Property: Total requests should equal sum of individual counts
          expect(metrics.totalRequests).toBe(
            metrics.blockedRequests + metrics.flaggedRequests + metrics.allowedRequests
          );

          // Property: Block rate should match the actual proportion of blocked requests
          if (metrics.totalRequests > 0) {
            const expectedBlockRate = (metrics.blockedRequests / metrics.totalRequests) * 100;
            expect(Math.abs(metrics.blockRate - expectedBlockRate)).toBeLessThan(0.01);
          }

          // Property: Bypass rate should match the actual proportion of allowed requests
          if (metrics.totalRequests > 0) {
            const expectedBypassRate = (metrics.allowedRequests / metrics.totalRequests) * 100;
            expect(Math.abs(metrics.bypassRate - expectedBypassRate)).toBeLessThan(0.01);
          }

          // Property: Average processing time should be positive if there are requests
          if (metrics.totalRequests > 0) {
            expect(metrics.averageProcessingTime).toBeGreaterThan(0);
          }

          // Property: Average risk score should be within valid range
          expect(metrics.averageRiskScore).toBeGreaterThanOrEqual(0);
          expect(metrics.averageRiskScore).toBeLessThanOrEqual(100);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should handle empty attack results gracefully', () => {
    fc.assert(
      fc.property(
        fc.constant([]), // Empty attack results
        fc.option(fc.array(firewallResponseArb, { minLength: 0, maxLength: 10 })),
        (attackResults, legitimateResponses) => {
          const legitimateResults: AttackResult[] | undefined = legitimateResponses?.map(response => ({
            attackId: uuidv4(),
            success: response.decision === 'ALLOW',
            firewallResponse: response,
            timestamp: new Date(),
            metrics: {
              processingTime: response.processingTime,
              confidence: response.attackCategory.confidence
            }
          }));

          const metrics = calculator.calculateMetrics(attackResults, legitimateResults);

          // Property: Empty results should still have complete metric structure
          expect(metrics).toBeDefined();
          expect(metrics.blockRate).toBe(0);
          expect(metrics.bypassRate).toBe(0);
          expect(metrics.totalRequests).toBe(0);
          expect(metrics.blockedRequests).toBe(0);
          expect(metrics.flaggedRequests).toBe(0);
          expect(metrics.allowedRequests).toBe(0);
          expect(metrics.averageProcessingTime).toBe(0);
          expect(metrics.averageRiskScore).toBe(0);

          // Property: False positive rate should be 0 if no legitimate results provided
          if (!legitimateResults || legitimateResults.length === 0) {
            expect(metrics.falsePositiveRate).toBe(0);
          }
        }
      ),
      { numRuns: 50 }
    );
  });

  it('should calculate false positive rate correctly when legitimate results are provided', () => {
    fc.assert(
      fc.property(
        fc.array(firewallResponseArb, { minLength: 1, maxLength: 50 }),
        fc.array(firewallResponseArb, { minLength: 1, maxLength: 50 }),
        (attackResponses, legitimateResponses) => {
          const attackResults: AttackResult[] = attackResponses.map(response => ({
            attackId: uuidv4(),
            success: response.decision === 'ALLOW',
            firewallResponse: response,
            timestamp: new Date(),
            metrics: {
              processingTime: response.processingTime,
              confidence: response.attackCategory.confidence
            }
          }));

          const legitimateResults: AttackResult[] = legitimateResponses.map(response => ({
            attackId: uuidv4(),
            success: response.decision === 'ALLOW',
            firewallResponse: response,
            timestamp: new Date(),
            metrics: {
              processingTime: response.processingTime,
              confidence: response.attackCategory.confidence
            }
          }));

          const metrics = calculator.calculateMetrics(attackResults, legitimateResults);

          // Property: False positive rate should be calculated based on legitimate results
          const incorrectlyFlagged = legitimateResults.filter(r => 
            r.firewallResponse.decision === 'BLOCK' || r.firewallResponse.decision === 'FLAG'
          ).length;
          const expectedFalsePositiveRate = (incorrectlyFlagged / legitimateResults.length) * 100;

          expect(Math.abs(metrics.falsePositiveRate - expectedFalsePositiveRate)).toBeLessThan(0.01);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should maintain metric consistency across different input sizes', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 1000 }),
        fc.constantFrom('ALLOW', 'BLOCK', 'FLAG'),
        fc.integer({ min: 0, max: 100 }),
        (numRequests, decision, riskScore) => {
          // Create uniform attack results with same decision and risk score
          const attackResults: AttackResult[] = Array.from({ length: numRequests }, () => ({
            attackId: uuidv4(),
            success: decision === 'ALLOW',
            firewallResponse: {
              decision,
              riskScore,
              attackCategory: {
                type: 'PROMPT_INJECTION',
                confidence: riskScore / 100,
                indicators: []
              },
              explanation: 'Test response',
              processingTime: 100,
              ruleVersion: 'test-1.0.0'
            },
            timestamp: new Date(),
            metrics: {
              processingTime: 100,
              confidence: riskScore / 100
            }
          }));

          const metrics = calculator.calculateMetrics(attackResults);

          // Property: Metrics should be consistent regardless of input size
          expect(metrics.totalRequests).toBe(numRequests);
          expect(metrics.averageRiskScore).toBeCloseTo(riskScore, 1);
          expect(metrics.averageProcessingTime).toBe(100);

          // Property: Rates should be consistent
          if (decision === 'BLOCK') {
            expect(metrics.blockRate).toBe(100);
            expect(metrics.bypassRate).toBe(0);
            expect(metrics.blockedRequests).toBe(numRequests);
            expect(metrics.allowedRequests).toBe(0);
          } else if (decision === 'ALLOW') {
            expect(metrics.blockRate).toBe(0);
            expect(metrics.bypassRate).toBe(100);
            expect(metrics.blockedRequests).toBe(0);
            expect(metrics.allowedRequests).toBe(numRequests);
          } else if (decision === 'FLAG') {
            expect(metrics.blockRate).toBe(0);
            expect(metrics.bypassRate).toBe(0);
            expect(metrics.flaggedRequests).toBe(numRequests);
          }
        }
      ),
      { numRuns: 100 }
    );
  });
});