/**
 * Evaluation Metrics and Reporting System
 * Implements block rate, false positive rate, and bypass rate calculations
 * Creates benchmark result presentation in tables and graphs
 * Adds export functionality for benchmark reports
 * Requirements: 7.2, 7.3, 7.5
 */

import { BenchmarkResult, BaselineResult, BaselineMetrics, BaselineComparison } from './benchmark';
import { AttackResult, FirewallResponse } from '../types/core';

export interface EvaluationMetrics {
  blockRate: number;           // Percentage of attacks successfully blocked
  falsePositiveRate: number;   // Percentage of legitimate requests incorrectly flagged
  bypassRate: number;          // Percentage of attacks that succeeded (allowed)
  averageProcessingTime: number;
  averageRiskScore: number;
  totalRequests: number;
  blockedRequests: number;
  flaggedRequests: number;
  allowedRequests: number;
}

export interface MetricsComparison {
  baseline1: string;
  baseline2: string;
  blockRateImprovement: number;
  bypassRateReduction: number;
  processingTimeChange: number;
  overallPerformanceGain: number;
}

export interface BenchmarkReport {
  id: string;
  title: string;
  executedAt: Date;
  summary: ReportSummary;
  baselineMetrics: Record<string, EvaluationMetrics>;
  comparisons: MetricsComparison[];
  visualizations: ReportVisualization[];
  recommendations: string[];
  exportFormats: ExportFormat[];
}

export interface ReportSummary {
  totalAttacksProcessed: number;
  bestPerformingBaseline: string;
  worstPerformingBaseline: string;
  significantFindings: string[];
  overallAssessment: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';
}

export interface ReportVisualization {
  type: 'TABLE' | 'BAR_CHART' | 'LINE_CHART' | 'COMPARISON_MATRIX';
  title: string;
  data: any;
  description: string;
}

export interface ExportFormat {
  format: 'JSON' | 'CSV' | 'HTML' | 'PDF';
  content: string;
  filename: string;
}

export class EvaluationMetricsCalculator {
  
  /**
   * Calculate comprehensive evaluation metrics from attack results
   */
  calculateMetrics(attackResults: AttackResult[], legitimateResults?: AttackResult[]): EvaluationMetrics {
    if (attackResults.length === 0) {
      return {
        blockRate: 0,
        falsePositiveRate: 0,
        bypassRate: 0,
        averageProcessingTime: 0,
        averageRiskScore: 0,
        totalRequests: 0,
        blockedRequests: 0,
        flaggedRequests: 0,
        allowedRequests: 0
      };
    }

    const blockedAttacks = attackResults.filter(r => r.firewallResponse.decision === 'BLOCK').length;
    const flaggedAttacks = attackResults.filter(r => r.firewallResponse.decision === 'FLAG').length;
    const allowedAttacks = attackResults.filter(r => r.firewallResponse.decision === 'ALLOW').length;

    const totalProcessingTime = attackResults.reduce((sum, r) => sum + r.firewallResponse.processingTime, 0);
    const totalRiskScore = attackResults.reduce((sum, r) => sum + r.firewallResponse.riskScore, 0);

    // Calculate false positive rate if legitimate results are provided
    let falsePositiveRate = 0;
    if (legitimateResults && legitimateResults.length > 0) {
      const incorrectlyFlagged = legitimateResults.filter(r => 
        r.firewallResponse.decision === 'BLOCK' || r.firewallResponse.decision === 'FLAG'
      ).length;
      falsePositiveRate = (incorrectlyFlagged / legitimateResults.length) * 100;
    }

    return {
      blockRate: (blockedAttacks / attackResults.length) * 100,
      falsePositiveRate,
      bypassRate: (allowedAttacks / attackResults.length) * 100,
      averageProcessingTime: totalProcessingTime / attackResults.length,
      averageRiskScore: totalRiskScore / attackResults.length,
      totalRequests: attackResults.length,
      blockedRequests: blockedAttacks,
      flaggedRequests: flaggedAttacks,
      allowedRequests: allowedAttacks
    };
  }

  /**
   * Compare metrics between two baselines
   */
  compareBaselines(baseline1: EvaluationMetrics, baseline2: EvaluationMetrics, name1: string, name2: string): MetricsComparison {
    const blockRateImprovement = baseline1.blockRate - baseline2.blockRate;
    const bypassRateReduction = baseline2.bypassRate - baseline1.bypassRate;
    const processingTimeChange = baseline1.averageProcessingTime - baseline2.averageProcessingTime;
    
    // Calculate overall performance gain (weighted score)
    const overallPerformanceGain = (blockRateImprovement * 0.4) + (bypassRateReduction * 0.4) + 
                                  (processingTimeChange > 0 ? -0.2 : 0.2); // Penalty for slower processing

    return {
      baseline1: name1,
      baseline2: name2,
      blockRateImprovement,
      bypassRateReduction,
      processingTimeChange,
      overallPerformanceGain
    };
  }

  /**
   * Generate performance assessment based on metrics
   */
  assessPerformance(metrics: EvaluationMetrics): 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR' {
    const score = (metrics.blockRate * 0.4) + ((100 - metrics.bypassRate) * 0.4) + 
                  ((100 - metrics.falsePositiveRate) * 0.2);

    if (score >= 90) return 'EXCELLENT';
    if (score >= 75) return 'GOOD';
    if (score >= 60) return 'FAIR';
    return 'POOR';
  }
}

export class BenchmarkReportGenerator {
  private metricsCalculator: EvaluationMetricsCalculator;

  constructor() {
    this.metricsCalculator = new EvaluationMetricsCalculator();
  }

  /**
   * Generate comprehensive benchmark report from results
   */
  generateReport(benchmarkResult: BenchmarkResult): BenchmarkReport {
    const baselineMetrics: Record<string, EvaluationMetrics> = {};
    const comparisons: MetricsComparison[] = [];

    // Calculate metrics for each baseline
    for (const baseline of benchmarkResult.baselineResults) {
      const metrics = this.metricsCalculator.calculateMetrics(baseline.attackResults);
      baselineMetrics[baseline.baselineType] = metrics;
    }

    // Generate pairwise comparisons
    const baselineNames = Object.keys(baselineMetrics);
    for (let i = 0; i < baselineNames.length; i++) {
      for (let j = i + 1; j < baselineNames.length; j++) {
        const comparison = this.metricsCalculator.compareBaselines(
          baselineMetrics[baselineNames[i]],
          baselineMetrics[baselineNames[j]],
          baselineNames[i],
          baselineNames[j]
        );
        comparisons.push(comparison);
      }
    }

    // Determine best and worst performing baselines
    const sortedBaselines = baselineNames.sort((a, b) => 
      baselineMetrics[b].blockRate - baselineMetrics[a].blockRate
    );

    const summary: ReportSummary = {
      totalAttacksProcessed: benchmarkResult.summary.totalAttacksProcessed,
      bestPerformingBaseline: sortedBaselines[0] || 'none',
      worstPerformingBaseline: sortedBaselines[sortedBaselines.length - 1] || 'none',
      significantFindings: this.generateFindings(baselineMetrics, comparisons),
      overallAssessment: this.metricsCalculator.assessPerformance(
        baselineMetrics[sortedBaselines[0]] || {
          blockRate: 0, falsePositiveRate: 0, bypassRate: 0, averageProcessingTime: 0,
          averageRiskScore: 0, totalRequests: 0, blockedRequests: 0, flaggedRequests: 0, allowedRequests: 0
        }
      )
    };

    const visualizations = this.generateVisualizations(baselineMetrics, comparisons);
    const recommendations = this.generateRecommendations(baselineMetrics, comparisons);

    const report: BenchmarkReport = {
      id: benchmarkResult.id,
      title: `Benchmark Report - ${benchmarkResult.executedAt.toISOString().split('T')[0]}`,
      executedAt: benchmarkResult.executedAt,
      summary,
      baselineMetrics,
      comparisons,
      visualizations,
      recommendations,
      exportFormats: []
    };

    // Generate export formats
    report.exportFormats = this.generateExportFormats(report);

    return report;
  }

  /**
   * Generate significant findings from metrics analysis
   */
  private generateFindings(baselineMetrics: Record<string, EvaluationMetrics>, comparisons: MetricsComparison[]): string[] {
    const findings: string[] = [];

    // Analyze block rate variations
    const blockRates = Object.values(baselineMetrics).map(m => m.blockRate);
    const maxBlockRate = Math.max(...blockRates);
    const minBlockRate = Math.min(...blockRates);
    
    if (maxBlockRate - minBlockRate > 20) {
      findings.push(`Significant variation in block rates: ${minBlockRate.toFixed(1)}% to ${maxBlockRate.toFixed(1)}%`);
    }

    // Analyze processing time differences
    const processingTimes = Object.values(baselineMetrics).map(m => m.averageProcessingTime);
    const maxTime = Math.max(...processingTimes);
    const minTime = Math.min(...processingTimes);
    
    if (maxTime > minTime * 2) {
      findings.push(`Processing time varies significantly: ${minTime.toFixed(1)}ms to ${maxTime.toFixed(1)}ms`);
    }

    // Analyze bypass rates
    const bypassRates = Object.values(baselineMetrics).map(m => m.bypassRate);
    const maxBypassRate = Math.max(...bypassRates);
    
    if (maxBypassRate > 50) {
      findings.push(`High bypass rate detected: ${maxBypassRate.toFixed(1)}% of attacks succeeded`);
    }

    // Analyze comparisons for significant improvements
    const significantComparisons = comparisons.filter(c => Math.abs(c.overallPerformanceGain) > 10);
    if (significantComparisons.length > 0) {
      findings.push(`${significantComparisons.length} significant performance differences found between baselines`);
    }

    return findings;
  }

  /**
   * Generate visualizations for the report
   */
  private generateVisualizations(baselineMetrics: Record<string, EvaluationMetrics>, comparisons: MetricsComparison[]): ReportVisualization[] {
    const visualizations: ReportVisualization[] = [];

    // Metrics comparison table
    visualizations.push({
      type: 'TABLE',
      title: 'Baseline Metrics Comparison',
      data: this.generateMetricsTable(baselineMetrics),
      description: 'Comprehensive comparison of key security metrics across all baselines'
    });

    // Block rate bar chart
    visualizations.push({
      type: 'BAR_CHART',
      title: 'Block Rate Comparison',
      data: this.generateBlockRateChart(baselineMetrics),
      description: 'Visual comparison of attack blocking effectiveness'
    });

    // Processing time comparison
    visualizations.push({
      type: 'BAR_CHART',
      title: 'Processing Time Comparison',
      data: this.generateProcessingTimeChart(baselineMetrics),
      description: 'Average processing time per request across baselines'
    });

    // Comparison matrix
    if (comparisons.length > 0) {
      visualizations.push({
        type: 'COMPARISON_MATRIX',
        title: 'Baseline Performance Matrix',
        data: this.generateComparisonMatrix(comparisons),
        description: 'Pairwise performance comparisons between baselines'
      });
    }

    return visualizations;
  }

  /**
   * Generate actionable recommendations
   */
  private generateRecommendations(baselineMetrics: Record<string, EvaluationMetrics>, comparisons: MetricsComparison[]): string[] {
    const recommendations: string[] = [];

    // Find best performing baseline
    const sortedBaselines = Object.entries(baselineMetrics).sort(([,a], [,b]) => b.blockRate - a.blockRate);
    const [bestBaseline, bestMetrics] = sortedBaselines[0] || ['none', null];

    if (bestMetrics) {
      if (bestMetrics.blockRate < 80) {
        recommendations.push('Consider implementing additional detection rules to improve block rate');
      }
      
      if (bestMetrics.bypassRate > 20) {
        recommendations.push('High bypass rate indicates potential gaps in attack detection');
      }
      
      if (bestMetrics.averageProcessingTime > 1000) {
        recommendations.push('Consider optimizing processing pipeline to reduce latency');
      }
      
      if (bestMetrics.falsePositiveRate > 5) {
        recommendations.push('Fine-tune detection algorithms to reduce false positive rate');
      }
    }

    // Analyze comparisons for improvement opportunities
    const significantImprovements = comparisons.filter(c => c.overallPerformanceGain > 15);
    if (significantImprovements.length > 0) {
      recommendations.push(`Consider adopting techniques from ${significantImprovements[0].baseline1} baseline for improved performance`);
    }

    // General recommendations
    if (Object.keys(baselineMetrics).length < 3) {
      recommendations.push('Consider testing against additional baseline configurations for comprehensive evaluation');
    }

    return recommendations;
  }

  /**
   * Generate export formats for the report
   */
  private generateExportFormats(report: BenchmarkReport): ExportFormat[] {
    const formats: ExportFormat[] = [];

    // JSON export
    formats.push({
      format: 'JSON',
      content: JSON.stringify(report, null, 2),
      filename: `benchmark-report-${report.id}.json`
    });

    // CSV export
    formats.push({
      format: 'CSV',
      content: this.generateCSVExport(report),
      filename: `benchmark-metrics-${report.id}.csv`
    });

    // HTML export
    formats.push({
      format: 'HTML',
      content: this.generateHTMLExport(report),
      filename: `benchmark-report-${report.id}.html`
    });

    return formats;
  }

  /**
   * Generate metrics comparison table data
   */
  private generateMetricsTable(baselineMetrics: Record<string, EvaluationMetrics>): any {
    const headers = ['Baseline', 'Block Rate (%)', 'Bypass Rate (%)', 'False Positive Rate (%)', 'Avg Processing Time (ms)', 'Avg Risk Score'];
    const rows = Object.entries(baselineMetrics).map(([name, metrics]) => [
      name,
      metrics.blockRate.toFixed(1),
      metrics.bypassRate.toFixed(1),
      metrics.falsePositiveRate.toFixed(1),
      metrics.averageProcessingTime.toFixed(1),
      metrics.averageRiskScore.toFixed(1)
    ]);

    return { headers, rows };
  }

  /**
   * Generate block rate chart data
   */
  private generateBlockRateChart(baselineMetrics: Record<string, EvaluationMetrics>): any {
    return {
      labels: Object.keys(baselineMetrics),
      values: Object.values(baselineMetrics).map(m => m.blockRate),
      type: 'bar',
      title: 'Block Rate by Baseline',
      yAxisLabel: 'Block Rate (%)'
    };
  }

  /**
   * Generate processing time chart data
   */
  private generateProcessingTimeChart(baselineMetrics: Record<string, EvaluationMetrics>): any {
    return {
      labels: Object.keys(baselineMetrics),
      values: Object.values(baselineMetrics).map(m => m.averageProcessingTime),
      type: 'bar',
      title: 'Average Processing Time by Baseline',
      yAxisLabel: 'Processing Time (ms)'
    };
  }

  /**
   * Generate comparison matrix data
   */
  private generateComparisonMatrix(comparisons: MetricsComparison[]): any {
    return {
      comparisons: comparisons.map(c => ({
        baseline1: c.baseline1,
        baseline2: c.baseline2,
        blockRateImprovement: c.blockRateImprovement.toFixed(1),
        bypassRateReduction: c.bypassRateReduction.toFixed(1),
        overallGain: c.overallPerformanceGain.toFixed(1)
      }))
    };
  }

  /**
   * Generate CSV export content
   */
  private generateCSVExport(report: BenchmarkReport): string {
    const lines: string[] = [];
    
    // Header
    lines.push('Benchmark Report CSV Export');
    lines.push(`Report ID: ${report.id}`);
    lines.push(`Executed At: ${report.executedAt.toISOString()}`);
    lines.push('');
    
    // Summary
    lines.push('SUMMARY');
    lines.push(`Total Attacks Processed: ${report.summary.totalAttacksProcessed}`);
    lines.push(`Best Performing Baseline: ${report.summary.bestPerformingBaseline}`);
    lines.push(`Overall Assessment: ${report.summary.overallAssessment}`);
    lines.push('');
    
    // Metrics table
    lines.push('BASELINE METRICS');
    lines.push('Baseline,Block Rate (%),Bypass Rate (%),False Positive Rate (%),Avg Processing Time (ms),Avg Risk Score');
    
    Object.entries(report.baselineMetrics).forEach(([name, metrics]) => {
      lines.push(`${name},${metrics.blockRate.toFixed(1)},${metrics.bypassRate.toFixed(1)},${metrics.falsePositiveRate.toFixed(1)},${metrics.averageProcessingTime.toFixed(1)},${metrics.averageRiskScore.toFixed(1)}`);
    });
    
    return lines.join('\n');
  }

  /**
   * Generate HTML export content
   */
  private generateHTMLExport(report: BenchmarkReport): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>${report.title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; }
        .metrics-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .metrics-table th, .metrics-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .metrics-table th { background-color: #f2f2f2; }
        .recommendation { background-color: #e7f3ff; padding: 10px; margin: 10px 0; border-radius: 3px; }
        .finding { background-color: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${report.title}</h1>
        <p><strong>Report ID:</strong> ${report.id}</p>
        <p><strong>Executed:</strong> ${report.executedAt.toISOString()}</p>
        <p><strong>Overall Assessment:</strong> ${report.summary.overallAssessment}</p>
    </div>
    
    <h2>Summary</h2>
    <ul>
        <li>Total Attacks Processed: ${report.summary.totalAttacksProcessed}</li>
        <li>Best Performing Baseline: ${report.summary.bestPerformingBaseline}</li>
        <li>Worst Performing Baseline: ${report.summary.worstPerformingBaseline}</li>
    </ul>
    
    <h2>Baseline Metrics</h2>
    <table class="metrics-table">
        <tr>
            <th>Baseline</th>
            <th>Block Rate (%)</th>
            <th>Bypass Rate (%)</th>
            <th>False Positive Rate (%)</th>
            <th>Avg Processing Time (ms)</th>
            <th>Avg Risk Score</th>
        </tr>
        ${Object.entries(report.baselineMetrics).map(([name, metrics]) => `
        <tr>
            <td>${name}</td>
            <td>${metrics.blockRate.toFixed(1)}</td>
            <td>${metrics.bypassRate.toFixed(1)}</td>
            <td>${metrics.falsePositiveRate.toFixed(1)}</td>
            <td>${metrics.averageProcessingTime.toFixed(1)}</td>
            <td>${metrics.averageRiskScore.toFixed(1)}</td>
        </tr>
        `).join('')}
    </table>
    
    <h2>Significant Findings</h2>
    ${report.summary.significantFindings.map(finding => `<div class="finding">${finding}</div>`).join('')}
    
    <h2>Recommendations</h2>
    ${report.recommendations.map(rec => `<div class="recommendation">${rec}</div>`).join('')}
</body>
</html>
    `.trim();
  }
}

export class BenchmarkExporter {
  private reportGenerator: BenchmarkReportGenerator;

  constructor() {
    this.reportGenerator = new BenchmarkReportGenerator();
  }

  /**
   * Export benchmark results in specified format
   */
  async exportBenchmarkResults(
    benchmarkResult: BenchmarkResult, 
    format: 'JSON' | 'CSV' | 'HTML' | 'PDF'
  ): Promise<ExportFormat> {
    const report = this.reportGenerator.generateReport(benchmarkResult);
    const exportFormat = report.exportFormats.find(f => f.format === format);
    
    if (!exportFormat) {
      throw new Error(`Export format ${format} not supported`);
    }
    
    return exportFormat;
  }

  /**
   * Export multiple benchmark results for comparison
   */
  async exportComparisonReport(
    benchmarkResults: BenchmarkResult[], 
    format: 'JSON' | 'CSV' | 'HTML'
  ): Promise<ExportFormat> {
    const reports = benchmarkResults.map(result => this.reportGenerator.generateReport(result));
    
    const comparisonData = {
      title: 'Benchmark Comparison Report',
      generatedAt: new Date().toISOString(),
      reports: reports.map(r => ({
        id: r.id,
        title: r.title,
        executedAt: r.executedAt,
        summary: r.summary,
        baselineMetrics: r.baselineMetrics
      }))
    };

    let content: string;
    let filename: string;

    switch (format) {
      case 'JSON':
        content = JSON.stringify(comparisonData, null, 2);
        filename = `benchmark-comparison-${Date.now()}.json`;
        break;
      case 'CSV':
        content = this.generateComparisonCSV(comparisonData);
        filename = `benchmark-comparison-${Date.now()}.csv`;
        break;
      case 'HTML':
        content = this.generateComparisonHTML(comparisonData);
        filename = `benchmark-comparison-${Date.now()}.html`;
        break;
      default:
        throw new Error(`Export format ${format} not supported for comparison reports`);
    }

    return { format, content, filename };
  }

  private generateComparisonCSV(data: any): string {
    const lines: string[] = [];
    
    lines.push('Benchmark Comparison Report');
    lines.push(`Generated At: ${data.generatedAt}`);
    lines.push('');
    lines.push('Report ID,Title,Executed At,Overall Assessment,Best Baseline,Total Attacks');
    
    data.reports.forEach((report: any) => {
      lines.push(`${report.id},${report.title},${report.executedAt},${report.summary.overallAssessment},${report.summary.bestPerformingBaseline},${report.summary.totalAttacksProcessed}`);
    });
    
    return lines.join('\n');
  }

  private generateComparisonHTML(data: any): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Benchmark Comparison Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; }
        .comparison-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .comparison-table th, .comparison-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .comparison-table th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Benchmark Comparison Report</h1>
        <p><strong>Generated:</strong> ${data.generatedAt}</p>
    </div>
    
    <table class="comparison-table">
        <tr>
            <th>Report ID</th>
            <th>Title</th>
            <th>Executed At</th>
            <th>Overall Assessment</th>
            <th>Best Baseline</th>
            <th>Total Attacks</th>
        </tr>
        ${data.reports.map((report: any) => `
        <tr>
            <td>${report.id}</td>
            <td>${report.title}</td>
            <td>${report.executedAt}</td>
            <td>${report.summary.overallAssessment}</td>
            <td>${report.summary.bestPerformingBaseline}</td>
            <td>${report.summary.totalAttacksProcessed}</td>
        </tr>
        `).join('')}
    </table>
</body>
</html>
    `.trim();
  }
}