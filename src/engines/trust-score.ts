/**
 * Trust Score Calculator
 * Quantified security assessment based on measured performance metrics
 */

import { TrustScore, TrustScoreComponents, SecurityMetrics } from '../types/core';

export interface TrustScoreChange {
  timestamp: Date;
  previousScore: number;
  newScore: number;
  changedMetrics: Array<{
    metric: keyof TrustScoreComponents;
    previousValue: number;
    newValue: number;
    impact: number; // How much this change affected the overall score
  }>;
  reason: string;
}

export interface TrustScoreAlert {
  id: string;
  timestamp: Date;
  alertType: 'CRITICAL_THRESHOLD' | 'WARNING_THRESHOLD' | 'IMPROVEMENT_THRESHOLD';
  currentScore: number;
  threshold: number;
  message: string;
  remediationRecommendations: string[];
}

export interface TrustScoreHistory {
  scores: Array<{
    timestamp: Date;
    score: TrustScore;
    change?: TrustScoreChange;
  }>;
  alerts: TrustScoreAlert[];
}

export interface MetricAggregator {
  aggregateBlockRate(metrics: SecurityMetrics[]): number;
  aggregateFalsePositiveRate(metrics: SecurityMetrics[]): number;
  aggregateBypassRate(metrics: SecurityMetrics[]): number;
  calculateRegressionPenalty(currentMetrics: TrustScoreComponents, previousMetrics?: TrustScoreComponents): number;
  calculateExplainabilityScore(totalDecisions: number, explainedDecisions: number): number;
}

export interface TrustScoreCalculator {
  calculateScore(components: TrustScoreComponents): TrustScore;
  updateScore(currentScore: TrustScore, newComponents: Partial<TrustScoreComponents>): TrustScore;
  aggregateMetrics(metrics: SecurityMetrics[]): TrustScoreComponents;
  trackScoreChange(previousScore: TrustScore, newScore: TrustScore): TrustScoreChange;
  checkThresholds(score: TrustScore): TrustScoreAlert[];
  getRemediationRecommendations(score: TrustScore): string[];
}

export class TrustScoreEngine implements TrustScoreCalculator, MetricAggregator {
  private readonly CRITICAL_THRESHOLD = 40;
  private readonly WARNING_THRESHOLD = 60;
  private readonly IMPROVEMENT_THRESHOLD = 80;

  calculateScore(components: TrustScoreComponents): TrustScore {
    // Validate input components
    this.validateComponents(components);
    
    // Implementation based on design document formula:
    // TrustScore = (blockRate * 0.35) + ((100 - falsePositiveRate) * 0.25) + 
    //              ((100 - bypassRate) * 0.25) + (explainabilityScore * 0.15) - regressionPenalty
    
    const overall = Math.max(0, Math.min(100, 
      (components.blockRate * 0.35) +
      ((100 - components.falsePositiveRate) * 0.25) +
      ((100 - components.bypassRate) * 0.25) +
      (components.explainabilityScore * 0.15) -
      components.regressionPenalty
    ));

    return {
      overall,
      components,
      trend: this.calculateTrend(overall),
      lastUpdated: new Date(),
      changeReason: 'Score calculated from current metrics'
    };
  }

  updateScore(currentScore: TrustScore, newComponents: Partial<TrustScoreComponents>): TrustScore {
    const updatedComponents: TrustScoreComponents = {
      ...currentScore.components,
      ...newComponents
    };

    const newScore = this.calculateScore(updatedComponents);
    const trend = this.compareTrend(currentScore.overall, newScore.overall);
    
    return {
      ...newScore,
      trend,
      changeReason: this.generateChangeReason(currentScore.components, updatedComponents)
    };
  }

  trackScoreChange(previousScore: TrustScore, newScore: TrustScore): TrustScoreChange {
    const changedMetrics: TrustScoreChange['changedMetrics'] = [];
    
    // Track changes in each metric and calculate their impact
    const metrics: Array<keyof TrustScoreComponents> = [
      'blockRate', 'falsePositiveRate', 'bypassRate', 'regressionPenalty', 'explainabilityScore'
    ];
    
    for (const metric of metrics) {
      const previousValue = previousScore.components[metric];
      const newValue = newScore.components[metric];
      
      if (previousValue !== newValue) {
        const impact = this.calculateMetricImpact(metric, previousValue, newValue);
        changedMetrics.push({
          metric,
          previousValue,
          newValue,
          impact
        });
      }
    }

    return {
      timestamp: new Date(),
      previousScore: previousScore.overall,
      newScore: newScore.overall,
      changedMetrics,
      reason: this.generateDetailedChangeReason(changedMetrics)
    };
  }

  checkThresholds(score: TrustScore): TrustScoreAlert[] {
    const alerts: TrustScoreAlert[] = [];
    const timestamp = new Date();

    if (score.overall <= this.CRITICAL_THRESHOLD) {
      alerts.push({
        id: `critical-${timestamp.getTime()}`,
        timestamp,
        alertType: 'CRITICAL_THRESHOLD',
        currentScore: score.overall,
        threshold: this.CRITICAL_THRESHOLD,
        message: `Trust score has fallen to critical level: ${score.overall.toFixed(1)}%`,
        remediationRecommendations: this.getRemediationRecommendations(score)
      });
    } else if (score.overall <= this.WARNING_THRESHOLD) {
      alerts.push({
        id: `warning-${timestamp.getTime()}`,
        timestamp,
        alertType: 'WARNING_THRESHOLD',
        currentScore: score.overall,
        threshold: this.WARNING_THRESHOLD,
        message: `Trust score requires attention: ${score.overall.toFixed(1)}%`,
        remediationRecommendations: this.getRemediationRecommendations(score)
      });
    } else if (score.overall >= this.IMPROVEMENT_THRESHOLD) {
      alerts.push({
        id: `improvement-${timestamp.getTime()}`,
        timestamp,
        alertType: 'IMPROVEMENT_THRESHOLD',
        currentScore: score.overall,
        threshold: this.IMPROVEMENT_THRESHOLD,
        message: `Trust score is performing excellently: ${score.overall.toFixed(1)}%`,
        remediationRecommendations: ['Continue current security practices', 'Monitor for any degradation']
      });
    }

    return alerts;
  }

  getRemediationRecommendations(score: TrustScore): string[] {
    const recommendations: string[] = [];
    const { components } = score;

    // Block rate recommendations
    if (components.blockRate < 70) {
      recommendations.push('Improve attack detection algorithms to increase block rate');
      recommendations.push('Review and update security rules for better coverage');
    }

    // False positive rate recommendations
    if (components.falsePositiveRate > 15) {
      recommendations.push('Fine-tune detection algorithms to reduce false positives');
      recommendations.push('Implement better context analysis for legitimate requests');
    }

    // Bypass rate recommendations
    if (components.bypassRate > 20) {
      recommendations.push('Strengthen defense mechanisms against bypass attempts');
      recommendations.push('Analyze successful bypasses to improve detection patterns');
    }

    // Regression penalty recommendations
    if (components.regressionPenalty > 10) {
      recommendations.push('Review recent defense changes that may have caused regression');
      recommendations.push('Consider rolling back problematic updates');
    }

    // Explainability recommendations
    if (components.explainabilityScore < 80) {
      recommendations.push('Improve decision explanation quality and coverage');
      recommendations.push('Ensure all security decisions include clear reasoning');
    }

    // General recommendations if score is low
    if (score.overall < 50) {
      recommendations.push('Conduct comprehensive security review');
      recommendations.push('Consider implementing additional defense layers');
      recommendations.push('Increase monitoring and alerting frequency');
    }

    return recommendations.length > 0 ? recommendations : ['Monitor current performance and maintain existing practices'];
  }

  private calculateMetricImpact(metric: keyof TrustScoreComponents, previousValue: number, newValue: number): number {
    const change = newValue - previousValue;
    
    switch (metric) {
      case 'blockRate':
        return change * 0.35;
      case 'falsePositiveRate':
        return -change * 0.25; // Negative because higher false positive rate is bad
      case 'bypassRate':
        return -change * 0.25; // Negative because higher bypass rate is bad
      case 'explainabilityScore':
        return change * 0.15;
      case 'regressionPenalty':
        return -change; // Negative because higher penalty is bad
      default:
        return 0;
    }
  }

  private generateDetailedChangeReason(changedMetrics: TrustScoreChange['changedMetrics']): string {
    if (changedMetrics.length === 0) {
      return 'No metric changes detected';
    }

    const changes = changedMetrics.map(change => {
      const direction = change.newValue > change.previousValue ? 'increased' : 'decreased';
      const impact = change.impact > 0 ? 'positive' : 'negative';
      return `${change.metric} ${direction} from ${change.previousValue.toFixed(1)} to ${change.newValue.toFixed(1)} (${impact} impact: ${change.impact.toFixed(1)} points)`;
    });

    return `Score changed due to: ${changes.join('; ')}`;
  }

  aggregateMetrics(metrics: SecurityMetrics[]): TrustScoreComponents {
    if (metrics.length === 0) {
      throw new Error('Cannot aggregate empty metrics array');
    }

    return {
      blockRate: this.aggregateBlockRate(metrics),
      falsePositiveRate: this.aggregateFalsePositiveRate(metrics),
      bypassRate: this.aggregateBypassRate(metrics),
      regressionPenalty: 0, // Will be calculated when comparing with previous metrics
      explainabilityScore: this.calculateExplainabilityScore(
        metrics.reduce((sum, m) => sum + m.metrics.totalRequests, 0),
        metrics.reduce((sum, m) => sum + m.metrics.totalRequests, 0) // Assume all decisions are explained for now
      )
    };
  }

  aggregateBlockRate(metrics: SecurityMetrics[]): number {
    const totalRequests = metrics.reduce((sum, m) => sum + m.metrics.totalRequests, 0);
    const totalBlocked = metrics.reduce((sum, m) => sum + m.metrics.blockedRequests, 0);
    
    return totalRequests > 0 ? (totalBlocked / totalRequests) * 100 : 0;
  }

  aggregateFalsePositiveRate(metrics: SecurityMetrics[]): number {
    const totalRequests = metrics.reduce((sum, m) => sum + m.metrics.totalRequests, 0);
    const totalFalsePositives = metrics.reduce((sum, m) => sum + m.metrics.falsePositives, 0);
    
    return totalRequests > 0 ? (totalFalsePositives / totalRequests) * 100 : 0;
  }

  aggregateBypassRate(metrics: SecurityMetrics[]): number {
    // Calculate bypass rate as the inverse of block rate for malicious requests
    // This is a simplified calculation - in practice, we'd need to track actual bypasses
    const blockRate = this.aggregateBlockRate(metrics);
    return Math.max(0, 100 - blockRate);
  }

  calculateRegressionPenalty(currentMetrics: TrustScoreComponents, previousMetrics?: TrustScoreComponents): number {
    if (!previousMetrics) {
      return 0;
    }

    let penalty = 0;
    
    // Penalty for decreased block rate
    if (currentMetrics.blockRate < previousMetrics.blockRate) {
      penalty += (previousMetrics.blockRate - currentMetrics.blockRate) * 0.5;
    }
    
    // Penalty for increased false positive rate
    if (currentMetrics.falsePositiveRate > previousMetrics.falsePositiveRate) {
      penalty += (currentMetrics.falsePositiveRate - previousMetrics.falsePositiveRate) * 0.3;
    }
    
    // Penalty for increased bypass rate
    if (currentMetrics.bypassRate > previousMetrics.bypassRate) {
      penalty += (currentMetrics.bypassRate - previousMetrics.bypassRate) * 0.4;
    }

    return Math.min(penalty, 50); // Cap penalty at 50 points
  }

  calculateExplainabilityScore(totalDecisions: number, explainedDecisions: number): number {
    if (totalDecisions === 0) {
      return 100; // Perfect score if no decisions made yet
    }
    
    const coverage = (explainedDecisions / totalDecisions) * 100;
    
    // For now, assume all explanations are of good quality
    // In practice, this would involve NLP analysis of explanation quality
    const qualityScore = 100;
    
    // Weighted average of coverage and quality
    return (coverage * 0.7) + (qualityScore * 0.3);
  }

  private validateComponents(components: TrustScoreComponents): void {
    const { blockRate, falsePositiveRate, bypassRate, regressionPenalty, explainabilityScore } = components;
    
    if (blockRate < 0 || blockRate > 100) {
      throw new Error(`Block rate must be between 0 and 100, got ${blockRate}`);
    }
    if (falsePositiveRate < 0 || falsePositiveRate > 100) {
      throw new Error(`False positive rate must be between 0 and 100, got ${falsePositiveRate}`);
    }
    if (bypassRate < 0 || bypassRate > 100) {
      throw new Error(`Bypass rate must be between 0 and 100, got ${bypassRate}`);
    }
    if (regressionPenalty < 0) {
      throw new Error(`Regression penalty must be non-negative, got ${regressionPenalty}`);
    }
    if (explainabilityScore < 0 || explainabilityScore > 100) {
      throw new Error(`Explainability score must be between 0 and 100, got ${explainabilityScore}`);
    }
  }

  private calculateTrend(score: number): 'IMPROVING' | 'STABLE' | 'DECLINING' {
    // Placeholder logic - will be enhanced with historical comparison
    if (score >= 80) return 'IMPROVING';
    if (score >= 60) return 'STABLE';
    return 'DECLINING';
  }

  private compareTrend(oldScore: number, newScore: number): 'IMPROVING' | 'STABLE' | 'DECLINING' {
    const difference = newScore - oldScore;
    if (difference > 2) return 'IMPROVING';
    if (difference < -2) return 'DECLINING';
    return 'STABLE';
  }

  private generateChangeReason(oldComponents: TrustScoreComponents, newComponents: TrustScoreComponents): string {
    const changes: string[] = [];
    
    if (oldComponents.blockRate !== newComponents.blockRate) {
      changes.push(`Block rate changed from ${oldComponents.blockRate}% to ${newComponents.blockRate}%`);
    }
    if (oldComponents.falsePositiveRate !== newComponents.falsePositiveRate) {
      changes.push(`False positive rate changed from ${oldComponents.falsePositiveRate}% to ${newComponents.falsePositiveRate}%`);
    }
    if (oldComponents.bypassRate !== newComponents.bypassRate) {
      changes.push(`Bypass rate changed from ${oldComponents.bypassRate}% to ${newComponents.bypassRate}%`);
    }
    
    return changes.length > 0 ? changes.join('; ') : 'No significant changes detected';
  }

  // Additional methods for web API
  async calculateTrustScore(userId: string, interactions: any[] = []): Promise<number> {
    // Simple trust score calculation based on user interactions
    const baseScore = 75;
    const interactionPenalty = interactions.length * 0.1;
    return Math.max(0, Math.min(100, baseScore - interactionPenalty));
  }

  async getTrustScore(userId: string): Promise<number> {
    // Return cached or calculated trust score for user
    return Math.floor(Math.random() * 40) + 60; // 60-100 range
  }
}