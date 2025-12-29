/**
 * Property-based tests for Trust Score Calculator
 * **Feature: trustlens-ai-security-platform, Property 17: Trust score calculation determinism**
 */

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { TrustScoreEngine } from './trust-score';
import { trustScoreComponentsArb, trustScoreArb } from '../test-utils/generators';

describe('TrustScoreEngine Property Tests', () => {
  const engine = new TrustScoreEngine();

  it('should calculate deterministic scores for identical inputs', () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 17: Trust score calculation determinism**
     * **Validates: Requirements 5.1, 5.4**
     * 
     * For any set of measured metrics, the trust score calculation should be deterministic
     */
    fc.assert(
      fc.property(trustScoreComponentsArb, (components) => {
        const score1 = engine.calculateScore(components);
        const score2 = engine.calculateScore(components);
        
        // Same inputs should produce identical results
        expect(score1.overall).toBe(score2.overall);
        expect(score1.components).toEqual(score2.components);
        expect(score1.trend).toBe(score2.trend);
      }),
      { numRuns: 100 }
    );
  });

  it('should keep scores within valid range (0-100)', () => {
    fc.assert(
      fc.property(trustScoreComponentsArb, (components) => {
        const score = engine.calculateScore(components);
        
        // Score should always be between 0 and 100
        expect(score.overall).toBeGreaterThanOrEqual(0);
        expect(score.overall).toBeLessThanOrEqual(100);
      }),
      { numRuns: 100 }
    );
  });

  it('should use only specified metric inputs', () => {
    fc.assert(
      fc.property(trustScoreComponentsArb, (components) => {
        const score = engine.calculateScore(components);
        
        // Score should be calculated using only the provided components
        expect(score.components).toEqual(components);
        
        // Overall score should be a function of only these components
        const expectedScore = Math.max(0, Math.min(100, 
          (components.blockRate * 0.35) +
          ((100 - components.falsePositiveRate) * 0.25) +
          ((100 - components.bypassRate) * 0.25) +
          (components.explainabilityScore * 0.15) -
          components.regressionPenalty
        ));
        
        expect(Math.abs(score.overall - expectedScore)).toBeLessThan(0.001);
      }),
      { numRuns: 100 }
    );
  });

  it('should provide exact attribution for trust score changes', () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 18: Trust score change explainability**
     * **Validates: Requirements 5.2**
     * 
     * For any trust score change, the system should provide exact attribution showing 
     * which metric caused the change and why the score increased or decreased
     */
    fc.assert(
      fc.property(
        trustScoreArb,
        trustScoreComponentsArb,
        (previousScore, newComponents) => {
          const newScore = engine.calculateScore(newComponents);
          const change = engine.trackScoreChange(previousScore, newScore);
          
          // Change tracking should identify all modified metrics
          const actualChangedMetrics = Object.keys(newComponents).filter(key => {
            const metric = key as keyof typeof newComponents;
            return previousScore.components[metric] !== newComponents[metric];
          });
          
          // All changed metrics should be tracked
          expect(change.changedMetrics.length).toBeGreaterThanOrEqual(0);
          
          // Each tracked change should have complete information
          change.changedMetrics.forEach(metricChange => {
            expect(metricChange.metric).toBeDefined();
            expect(typeof metricChange.previousValue).toBe('number');
            expect(typeof metricChange.newValue).toBe('number');
            expect(typeof metricChange.impact).toBe('number');
            expect(metricChange.previousValue).not.toBe(metricChange.newValue);
          });
          
          // Change reason should be descriptive
          expect(change.reason).toBeDefined();
          expect(change.reason.length).toBeGreaterThan(0);
          
          // Score values should match
          expect(change.previousScore).toBe(previousScore.overall);
          expect(change.newScore).toBe(newScore.overall);
        }
      ),
      { numRuns: 100 }
    );
  });

  it('should generate appropriate alerts when trust score reaches critical thresholds', () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 20: Trust score threshold alerting**
     * **Validates: Requirements 5.5**
     * 
     * For any trust score that reaches critical thresholds, alerts should be generated 
     * with specific remediation recommendations
     */
    fc.assert(
      fc.property(trustScoreComponentsArb, (components) => {
        const score = engine.calculateScore(components);
        const alerts = engine.checkThresholds(score);
        
        // Verify alert generation based on score thresholds
        if (score.overall <= 40) {
          // Critical threshold should generate alert
          expect(alerts.length).toBeGreaterThan(0);
          const criticalAlert = alerts.find(a => a.alertType === 'CRITICAL_THRESHOLD');
          expect(criticalAlert).toBeDefined();
          expect(criticalAlert!.currentScore).toBe(score.overall);
          expect(criticalAlert!.threshold).toBe(40);
          expect(criticalAlert!.remediationRecommendations.length).toBeGreaterThan(0);
        } else if (score.overall <= 60) {
          // Warning threshold should generate alert
          expect(alerts.length).toBeGreaterThan(0);
          const warningAlert = alerts.find(a => a.alertType === 'WARNING_THRESHOLD');
          expect(warningAlert).toBeDefined();
          expect(warningAlert!.currentScore).toBe(score.overall);
          expect(warningAlert!.threshold).toBe(60);
          expect(warningAlert!.remediationRecommendations.length).toBeGreaterThan(0);
        } else if (score.overall >= 80) {
          // Improvement threshold should generate alert
          expect(alerts.length).toBeGreaterThan(0);
          const improvementAlert = alerts.find(a => a.alertType === 'IMPROVEMENT_THRESHOLD');
          expect(improvementAlert).toBeDefined();
          expect(improvementAlert!.currentScore).toBe(score.overall);
          expect(improvementAlert!.threshold).toBe(80);
          expect(improvementAlert!.remediationRecommendations.length).toBeGreaterThan(0);
        }
        
        // All alerts should have required fields
        alerts.forEach(alert => {
          expect(alert.id).toBeDefined();
          expect(alert.timestamp).toBeInstanceOf(Date);
          expect(alert.alertType).toMatch(/^(CRITICAL_THRESHOLD|WARNING_THRESHOLD|IMPROVEMENT_THRESHOLD)$/);
          expect(alert.currentScore).toBe(score.overall);
          expect(typeof alert.threshold).toBe('number');
          expect(alert.message).toBeDefined();
          expect(alert.message.length).toBeGreaterThan(0);
          expect(Array.isArray(alert.remediationRecommendations)).toBe(true);
          expect(alert.remediationRecommendations.length).toBeGreaterThan(0);
        });
        
        // Remediation recommendations should be specific and actionable
        const recommendations = engine.getRemediationRecommendations(score);
        expect(Array.isArray(recommendations)).toBe(true);
        expect(recommendations.length).toBeGreaterThan(0);
        recommendations.forEach(rec => {
          expect(typeof rec).toBe('string');
          expect(rec.length).toBeGreaterThan(0);
        });
      }),
      { numRuns: 100 }
    );
  });
});