/**
 * Unit tests for Evaluation Metrics and Reporting System
 * Testing block rate, false positive rate, and bypass rate calculations
 * Testing benchmark result presentation and export functionality
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { 
  EvaluationMetricsCalculator, 
  BenchmarkReportGenerator, 
  BenchmarkExporter 
} from './evaluation-metrics';
import { AttackResult, FirewallResponse } from '../types/core';
import { BenchmarkResult, BaselineResult } from './benchmark';
import { v4 as uuidv4 } from 'uuid';

describe('Evaluation Metrics Calculator', () => {
  let calculator: EvaluationMetricsCalculator;

  beforeEach(() => {
    calculator = new EvaluationMetricsCalculator();
  });

  it('should calculate metrics correctly for empty results', () => {
    const metrics = calculator.calculateMetrics([]);
    
    expect(metrics.blockRate).toBe(0);
    expect(metrics.bypassRate).toBe(0);
    expect(metrics.falsePositiveRate).toBe(0);
    expect(metrics.totalRequests).toBe(0);
  });

  it('should calculate block rate correctly', () => {
    const attackResults: AttackResult[] = [
      createAttackResult('BLOCK', 80),
      createAttackResult('BLOCK', 90),
      createAttackResult('ALLOW', 20),
      createAttackResult('FLAG', 60)
    ];

    const metrics = calculator.calculateMetrics(attackResults);
    
    expect(metrics.blockRate).toBe(50); // 2 out of 4 blocked
    expect(metrics.bypassRate).toBe(25); // 1 out of 4 allowed
    expect(metrics.totalRequests).toBe(4);
    expect(metrics.blockedRequests).toBe(2);
    expect(metrics.allowedRequests).toBe(1);
    expect(metrics.flaggedRequests).toBe(1);
  });

  it('should calculate false positive rate with legitimate results', () => {
    const attackResults: AttackResult[] = [
      createAttackResult('BLOCK', 80),
      createAttackResult('ALLOW', 20)
    ];

    const legitimateResults: AttackResult[] = [
      createAttackResult('ALLOW', 10),
      createAttackResult('BLOCK', 70), // False positive
      createAttackResult('ALLOW', 15),
      createAttackResult('FLAG', 30)   // False positive
    ];

    const metrics = calculator.calculateMetrics(attackResults, legitimateResults);
    
    expect(metrics.falsePositiveRate).toBe(50); // 2 out of 4 legitimate requests incorrectly flagged
  });

  it('should calculate average processing time and risk score', () => {
    const attackResults: AttackResult[] = [
      createAttackResult('BLOCK', 80, 100),
      createAttackResult('ALLOW', 20, 200),
      createAttackResult('FLAG', 60, 150)
    ];

    const metrics = calculator.calculateMetrics(attackResults);
    
    expect(metrics.averageProcessingTime).toBe(150); // (100 + 200 + 150) / 3
    expect(metrics.averageRiskScore).toBeCloseTo(53.33, 1); // (80 + 20 + 60) / 3, rounded
  });

  it('should compare baselines correctly', () => {
    const baseline1 = calculator.calculateMetrics([
      createAttackResult('BLOCK', 80),
      createAttackResult('BLOCK', 90),
      createAttackResult('ALLOW', 20)
    ]);

    const baseline2 = calculator.calculateMetrics([
      createAttackResult('BLOCK', 70),
      createAttackResult('ALLOW', 30),
      createAttackResult('ALLOW', 40)
    ]);

    const comparison = calculator.compareBaselines(baseline1, baseline2, 'firewall', 'no-defense');
    
    expect(comparison.baseline1).toBe('firewall');
    expect(comparison.baseline2).toBe('no-defense');
    expect(comparison.blockRateImprovement).toBeCloseTo(33.33, 1); // 66.67 - 33.33
    expect(comparison.bypassRateReduction).toBeCloseTo(33.33, 1); // 66.67 - 33.33
  });

  it('should assess performance correctly', () => {
    const excellentMetrics = calculator.calculateMetrics([
      createAttackResult('BLOCK', 95),
      createAttackResult('BLOCK', 98),
      createAttackResult('BLOCK', 92)
    ]);

    const poorMetrics = calculator.calculateMetrics([
      createAttackResult('ALLOW', 10),
      createAttackResult('ALLOW', 20),
      createAttackResult('ALLOW', 15)
    ]);

    expect(calculator.assessPerformance(excellentMetrics)).toBe('EXCELLENT');
    expect(calculator.assessPerformance(poorMetrics)).toBe('POOR');
  });
});

describe('Benchmark Report Generator', () => {
  let generator: BenchmarkReportGenerator;

  beforeEach(() => {
    generator = new BenchmarkReportGenerator();
  });

  it('should generate a complete report', () => {
    const benchmarkResult = createMockBenchmarkResult();
    const report = generator.generateReport(benchmarkResult);

    expect(report.id).toBe(benchmarkResult.id);
    expect(report.title).toContain('Benchmark Report');
    expect(report.summary).toBeDefined();
    expect(report.baselineMetrics).toBeDefined();
    expect(report.comparisons).toBeDefined();
    expect(report.visualizations).toBeDefined();
    expect(report.recommendations).toBeDefined();
    expect(report.exportFormats).toBeDefined();
  });

  it('should identify best and worst performing baselines', () => {
    const benchmarkResult = createMockBenchmarkResult();
    const report = generator.generateReport(benchmarkResult);

    expect(report.summary.bestPerformingBaseline).toBeDefined();
    expect(report.summary.worstPerformingBaseline).toBeDefined();
    expect(report.summary.overallAssessment).toMatch(/EXCELLENT|GOOD|FAIR|POOR/);
  });

  it('should generate visualizations', () => {
    const benchmarkResult = createMockBenchmarkResult();
    const report = generator.generateReport(benchmarkResult);

    expect(report.visualizations.length).toBeGreaterThanOrEqual(3); // At least Table, Block Rate Chart, Processing Time Chart
    expect(report.visualizations[0].type).toBe('TABLE');
    expect(report.visualizations[1].type).toBe('BAR_CHART');
    expect(report.visualizations[2].type).toBe('BAR_CHART');
  });

  it('should generate export formats', () => {
    const benchmarkResult = createMockBenchmarkResult();
    const report = generator.generateReport(benchmarkResult);

    expect(report.exportFormats).toHaveLength(3); // JSON, CSV, HTML
    
    const jsonExport = report.exportFormats.find(f => f.format === 'JSON');
    const csvExport = report.exportFormats.find(f => f.format === 'CSV');
    const htmlExport = report.exportFormats.find(f => f.format === 'HTML');

    expect(jsonExport).toBeDefined();
    expect(csvExport).toBeDefined();
    expect(htmlExport).toBeDefined();
    
    expect(jsonExport!.content).toContain(report.id);
    expect(csvExport!.content).toContain('BASELINE METRICS');
    expect(htmlExport!.content).toContain('<html>');
  });
});

describe('Benchmark Exporter', () => {
  let exporter: BenchmarkExporter;

  beforeEach(() => {
    exporter = new BenchmarkExporter();
  });

  it('should export benchmark results in JSON format', async () => {
    const benchmarkResult = createMockBenchmarkResult();
    const exportFormat = await exporter.exportBenchmarkResults(benchmarkResult, 'JSON');

    expect(exportFormat.format).toBe('JSON');
    expect(exportFormat.filename).toContain('.json');
    expect(exportFormat.content).toContain(benchmarkResult.id);
    
    // Verify it's valid JSON
    expect(() => JSON.parse(exportFormat.content)).not.toThrow();
  });

  it('should export benchmark results in CSV format', async () => {
    const benchmarkResult = createMockBenchmarkResult();
    const exportFormat = await exporter.exportBenchmarkResults(benchmarkResult, 'CSV');

    expect(exportFormat.format).toBe('CSV');
    expect(exportFormat.filename).toContain('.csv');
    expect(exportFormat.content).toContain('BASELINE METRICS');
    expect(exportFormat.content).toContain('Block Rate (%)');
  });

  it('should export benchmark results in HTML format', async () => {
    const benchmarkResult = createMockBenchmarkResult();
    const exportFormat = await exporter.exportBenchmarkResults(benchmarkResult, 'HTML');

    expect(exportFormat.format).toBe('HTML');
    expect(exportFormat.filename).toContain('.html');
    expect(exportFormat.content).toContain('<html>');
    expect(exportFormat.content).toContain(benchmarkResult.id);
  });

  it('should export comparison report for multiple results', async () => {
    const results = [createMockBenchmarkResult(), createMockBenchmarkResult()];
    const exportFormat = await exporter.exportComparisonReport(results, 'JSON');

    expect(exportFormat.format).toBe('JSON');
    expect(exportFormat.filename).toContain('comparison');
    expect(exportFormat.content).toContain('Benchmark Comparison Report');
    
    const parsed = JSON.parse(exportFormat.content);
    expect(parsed.reports).toHaveLength(2);
  });

  it('should throw error for unsupported export format', async () => {
    const benchmarkResult = createMockBenchmarkResult();
    
    await expect(
      exporter.exportBenchmarkResults(benchmarkResult, 'PDF' as any)
    ).rejects.toThrow('Export format PDF not supported');
  });
});

// Helper functions
function createAttackResult(decision: 'ALLOW' | 'BLOCK' | 'FLAG', riskScore: number, processingTime: number = 100): AttackResult {
  const response: FirewallResponse = {
    decision,
    riskScore,
    attackCategory: {
      type: 'PROMPT_INJECTION',
      confidence: riskScore / 100,
      indicators: []
    },
    explanation: `Test response with ${decision} decision`,
    processingTime,
    ruleVersion: 'test-1.0.0'
  };

  return {
    attackId: uuidv4(),
    success: decision === 'ALLOW',
    firewallResponse: response,
    timestamp: new Date(),
    metrics: {
      processingTime,
      confidence: riskScore / 100
    }
  };
}

function createMockBenchmarkResult(): BenchmarkResult {
  const baselineResults: BaselineResult[] = [
    {
      baselineType: 'current-firewall',
      attackResults: [
        createAttackResult('BLOCK', 80),
        createAttackResult('BLOCK', 90),
        createAttackResult('ALLOW', 20)
      ],
      metrics: {
        totalAttacks: 3,
        blockedAttacks: 2,
        flaggedAttacks: 0,
        allowedAttacks: 1,
        blockRate: 66.67,
        falsePositiveRate: 0,
        bypassRate: 33.33,
        averageProcessingTime: 100,
        averageRiskScore: 63.33
      },
      executionTimeMs: 1000,
      errors: []
    },
    {
      baselineType: 'no-defense',
      attackResults: [
        createAttackResult('ALLOW', 0),
        createAttackResult('ALLOW', 0),
        createAttackResult('ALLOW', 0)
      ],
      metrics: {
        totalAttacks: 3,
        blockedAttacks: 0,
        flaggedAttacks: 0,
        allowedAttacks: 3,
        blockRate: 0,
        falsePositiveRate: 0,
        bypassRate: 100,
        averageProcessingTime: 50,
        averageRiskScore: 0
      },
      executionTimeMs: 500,
      errors: []
    }
  ];

  return {
    id: uuidv4(),
    configurationId: uuidv4(),
    executedAt: new Date(),
    completedAt: new Date(),
    status: 'COMPLETED',
    baselineResults,
    summary: {
      totalAttacksProcessed: 6,
      totalExecutionTimeMs: 1500,
      baselineComparison: [],
      topPerformingBaseline: 'current-firewall',
      significantFindings: []
    },
    reproducibilityHash: 'test-hash'
  };
}