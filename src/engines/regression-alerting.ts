/**
 * Regression Alerting and Reporting System
 * Implements regression detection algorithms, alert generation, and comprehensive reporting
 */

import { 
  RegressionAlert, 
  RegressionReport, 
  PerformanceImpact, 
  RegressionSummary,
  DetailedComparison,
  AttackRegressionDetail,
  RecommendationSection,
  DefenseVersion,
  AttackResult,
  RegressionTest,
  AuditLogEntry
} from '../types/core';
import { SQLiteDatabase } from '../data/database';
import { DefenseVersioningService, PerformanceComparison } from './defense-versioning';
import { v4 as uuidv4 } from 'uuid';

export interface RegressionAlertingSystem {
  analyzeRegression(currentVersion: string, previousVersion: string, regressionTest: RegressionTest): Promise<RegressionAlert[]>;
  generateRegressionReport(currentVersion: string, previousVersion: string, regressionTest: RegressionTest): Promise<RegressionReport>;
  getActiveAlerts(): Promise<RegressionAlert[]>;
  acknowledgeAlert(alertId: string): Promise<void>;
  exportReport(reportId: string, format: 'JSON' | 'CSV' | 'HTML'): Promise<string>;
}

export class RegressionAlertingService implements RegressionAlertingSystem {
  private database: SQLiteDatabase;
  private versioningService: DefenseVersioningService;

  constructor(database?: SQLiteDatabase, versioningService?: DefenseVersioningService) {
    this.database = database || new SQLiteDatabase();
    this.versioningService = versioningService || new DefenseVersioningService(this.database);
  }

  async initialize(): Promise<void> {
    if (!this.database.isConnected()) {
      await this.database.connect();
    }
    await this.initializeAlertingTables();
  }

  private async initializeAlertingTables(): Promise<void> {
    const tables = [
      `CREATE TABLE IF NOT EXISTS regression_alerts (
        id TEXT PRIMARY KEY,
        defense_version TEXT NOT NULL,
        previous_version TEXT NOT NULL,
        severity TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        message TEXT NOT NULL,
        affected_attacks TEXT NOT NULL,
        performance_impact TEXT NOT NULL,
        remediation_recommendations TEXT NOT NULL,
        created_at TEXT NOT NULL,
        acknowledged INTEGER DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS regression_reports (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        defense_version TEXT NOT NULL,
        previous_version TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        summary TEXT NOT NULL,
        detailed_comparison TEXT NOT NULL,
        affected_attacks TEXT NOT NULL,
        recommendations TEXT NOT NULL,
        export_formats TEXT NOT NULL
      )`
    ];

    for (const sql of tables) {
      await this.database.executeQuery(sql);
    }
  }

  async analyzeRegression(
    currentVersion: string, 
    previousVersion: string, 
    regressionTest: RegressionTest
  ): Promise<RegressionAlert[]> {
    const alerts: RegressionAlert[] = [];

    // Get performance comparison between versions
    const comparison = await this.versioningService.compareDefensePerformance(
      previousVersion,
      currentVersion
    );

    // Calculate performance impact
    const performanceImpact = this.calculatePerformanceImpact(comparison);

    // Generate alerts based on different regression types
    const blockRateAlert = this.analyzeBlockRateRegression(
      currentVersion, previousVersion, comparison, performanceImpact, regressionTest
    );
    if (blockRateAlert) alerts.push(blockRateAlert);

    const bypassRateAlert = this.analyzeBypassRateRegression(
      currentVersion, previousVersion, comparison, performanceImpact, regressionTest
    );
    if (bypassRateAlert) alerts.push(bypassRateAlert);

    const performanceAlert = this.analyzePerformanceRegression(
      currentVersion, previousVersion, comparison, performanceImpact, regressionTest
    );
    if (performanceAlert) alerts.push(performanceAlert);

    const criticalAlert = this.analyzeCriticalRegression(
      currentVersion, previousVersion, comparison, performanceImpact, regressionTest
    );
    if (criticalAlert) alerts.push(criticalAlert);

    // Store alerts in database
    for (const alert of alerts) {
      await this.storeAlert(alert);
      await this.logAlertGeneration(alert);
    }

    return alerts;
  }

  async generateRegressionReport(
    currentVersion: string, 
    previousVersion: string, 
    regressionTest: RegressionTest
  ): Promise<RegressionReport> {
    const reportId = uuidv4();
    const generatedAt = new Date();

    // Get performance comparison
    const comparison = await this.versioningService.compareDefensePerformance(
      previousVersion,
      currentVersion
    );

    // Get defense versions for detailed metrics
    const currentDefense = await this.versioningService.getDefenseVersion(currentVersion);
    const previousDefense = await this.versioningService.getDefenseVersion(previousVersion);

    if (!currentDefense || !previousDefense) {
      throw new Error(`Defense versions not found: ${currentVersion} or ${previousVersion}`);
    }

    // Generate summary
    const summary = this.generateRegressionSummary(comparison, regressionTest);

    // Generate detailed comparison
    const detailedComparison = this.generateDetailedComparison(
      previousDefense, currentDefense, comparison
    );

    // Analyze affected attacks
    const affectedAttacks = this.analyzeAffectedAttacks(regressionTest);

    // Generate recommendations
    const recommendations = this.generateRecommendations(summary, detailedComparison, affectedAttacks);

    const report: RegressionReport = {
      id: reportId,
      title: `Regression Analysis: ${previousVersion} → ${currentVersion}`,
      defenseVersion: currentVersion,
      previousVersion,
      generatedAt,
      summary,
      detailedComparison,
      affectedAttacks,
      recommendations,
      exportFormats: ['JSON', 'CSV', 'HTML']
    };

    // Store report in database
    await this.storeReport(report);

    return report;
  }

  async getActiveAlerts(): Promise<RegressionAlert[]> {
    const rows = await this.database.executeQuery(
      'SELECT * FROM regression_alerts WHERE acknowledged = 0 ORDER BY created_at DESC'
    );

    return rows.map(row => this.parseAlertFromRow(row));
  }

  async acknowledgeAlert(alertId: string): Promise<void> {
    await this.database.executeQuery(
      'UPDATE regression_alerts SET acknowledged = 1 WHERE id = ?',
      [alertId]
    );

    // Log alert acknowledgment
    const logEntry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      eventType: 'DEFENSE_UPDATED',
      data: {
        // Store alert acknowledgment info in a way that fits existing schema
        trustScoreChange: 0
      },
      metadata: {
        processingTime: 0
      }
    };

    await this.database.insertLogEntry(logEntry);
  }

  async exportReport(reportId: string, format: 'JSON' | 'CSV' | 'HTML'): Promise<string> {
    const rows = await this.database.executeQuery(
      'SELECT * FROM regression_reports WHERE id = ?',
      [reportId]
    );

    if (rows.length === 0) {
      throw new Error(`Report ${reportId} not found`);
    }

    const report = this.parseReportFromRow(rows[0]);

    switch (format) {
      case 'JSON':
        return JSON.stringify(report, null, 2);
      case 'CSV':
        return this.exportReportAsCSV(report);
      case 'HTML':
        return this.exportReportAsHTML(report);
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  private calculatePerformanceImpact(comparison: PerformanceComparison): PerformanceImpact {
    // Calculate overall impact score (0-100, higher is worse)
    let impactScore = 0;
    
    // Block rate decrease is bad
    if (comparison.blockRateDiff < 0) {
      impactScore += Math.abs(comparison.blockRateDiff) * 2;
    }
    
    // Bypass rate increase is bad
    if (comparison.bypassRateDiff > 0) {
      impactScore += comparison.bypassRateDiff * 2;
    }
    
    // False positive rate increase is bad
    if (comparison.falsePositiveRateDiff > 0) {
      impactScore += comparison.falsePositiveRateDiff * 1.5;
    }
    
    // Processing time increase is bad
    if (comparison.processingTimeDiff > 0) {
      impactScore += (comparison.processingTimeDiff / 100) * 10; // Scale processing time impact
    }
    
    // Throughput decrease is bad
    if (comparison.throughputDiff < 0) {
      impactScore += Math.abs(comparison.throughputDiff) * 0.5;
    }

    return {
      blockRateChange: comparison.blockRateDiff,
      bypassRateChange: comparison.bypassRateDiff,
      falsePositiveRateChange: comparison.falsePositiveRateDiff,
      processingTimeChange: comparison.processingTimeDiff,
      throughputChange: comparison.throughputDiff,
      overallImpactScore: Math.min(100, Math.max(0, impactScore))
    };
  }

  private analyzeBlockRateRegression(
    currentVersion: string,
    previousVersion: string,
    comparison: PerformanceComparison,
    impact: PerformanceImpact,
    regressionTest: RegressionTest
  ): RegressionAlert | null {
    if (comparison.blockRateDiff >= -5) return null; // No significant decrease

    const severity = this.determineSeverity(Math.abs(comparison.blockRateDiff), 'BLOCK_RATE');
    
    return {
      id: uuidv4(),
      defenseVersion: currentVersion,
      previousVersion,
      severity,
      alertType: 'BLOCK_RATE_DECREASE',
      message: `Block rate decreased by ${Math.abs(comparison.blockRateDiff).toFixed(1)}% from ${previousVersion} to ${currentVersion}`,
      affectedAttacks: regressionTest.affectedAttacks,
      performanceImpact: impact,
      remediationRecommendations: [
        'Review new defense rules for gaps in attack detection',
        'Consider strengthening detection patterns for affected attack types',
        'Evaluate rollback to previous version if impact is critical',
        'Monitor attack success rates closely for next 24 hours'
      ],
      createdAt: new Date(),
      acknowledged: false
    };
  }

  private analyzeBypassRateRegression(
    currentVersion: string,
    previousVersion: string,
    comparison: PerformanceComparison,
    impact: PerformanceImpact,
    regressionTest: RegressionTest
  ): RegressionAlert | null {
    if (comparison.bypassRateDiff <= 5) return null; // No significant increase

    const severity = this.determineSeverity(comparison.bypassRateDiff, 'BYPASS_RATE');
    
    return {
      id: uuidv4(),
      defenseVersion: currentVersion,
      previousVersion,
      severity,
      alertType: 'BYPASS_RATE_INCREASE',
      message: `Bypass rate increased by ${comparison.bypassRateDiff.toFixed(1)}% from ${previousVersion} to ${currentVersion}`,
      affectedAttacks: regressionTest.affectedAttacks,
      performanceImpact: impact,
      remediationRecommendations: [
        'Analyze bypassed attacks to identify common patterns',
        'Update defense rules to address new bypass techniques',
        'Implement additional detection layers for high-risk attack types',
        'Consider temporary blocking of suspicious patterns while rules are updated'
      ],
      createdAt: new Date(),
      acknowledged: false
    };
  }

  private analyzePerformanceRegression(
    currentVersion: string,
    previousVersion: string,
    comparison: PerformanceComparison,
    impact: PerformanceImpact,
    regressionTest: RegressionTest
  ): RegressionAlert | null {
    // Check for significant performance degradation
    const significantProcessingIncrease = comparison.processingTimeDiff > 50; // 50ms increase
    const significantThroughputDecrease = comparison.throughputDiff < -2; // 2 req/s decrease

    if (!significantProcessingIncrease && !significantThroughputDecrease) return null;

    const severity = this.determineSeverity(impact.overallImpactScore, 'PERFORMANCE');
    
    return {
      id: uuidv4(),
      defenseVersion: currentVersion,
      previousVersion,
      severity,
      alertType: 'PERFORMANCE_DEGRADATION',
      message: `Performance degradation detected: processing time increased by ${comparison.processingTimeDiff.toFixed(1)}ms, throughput changed by ${comparison.throughputDiff.toFixed(1)} req/s`,
      affectedAttacks: [],
      performanceImpact: impact,
      remediationRecommendations: [
        'Profile defense rule execution to identify bottlenecks',
        'Optimize complex regex patterns in security rules',
        'Consider rule ordering optimization for common attack patterns',
        'Monitor system resources and scale if necessary'
      ],
      createdAt: new Date(),
      acknowledged: false
    };
  }

  private analyzeCriticalRegression(
    currentVersion: string,
    previousVersion: string,
    comparison: PerformanceComparison,
    impact: PerformanceImpact,
    regressionTest: RegressionTest
  ): RegressionAlert | null {
    // Critical regression: major block rate decrease AND bypass rate increase
    const criticalBlockRateDecrease = comparison.blockRateDiff < -15;
    const criticalBypassRateIncrease = comparison.bypassRateDiff > 15;
    const manyAffectedAttacks = regressionTest.affectedAttacks.length > 10;

    if (!criticalBlockRateDecrease && !criticalBypassRateIncrease && !manyAffectedAttacks) return null;

    return {
      id: uuidv4(),
      defenseVersion: currentVersion,
      previousVersion,
      severity: 'CRITICAL',
      alertType: 'CRITICAL_REGRESSION',
      message: `CRITICAL REGRESSION: Major security degradation detected. Block rate decreased by ${Math.abs(comparison.blockRateDiff).toFixed(1)}%, bypass rate increased by ${comparison.bypassRateDiff.toFixed(1)}%, ${regressionTest.affectedAttacks.length} attacks now bypass defenses.`,
      affectedAttacks: regressionTest.affectedAttacks,
      performanceImpact: impact,
      remediationRecommendations: [
        'IMMEDIATE ACTION REQUIRED: Consider emergency rollback to previous version',
        'Halt deployment of current defense version to production',
        'Conduct urgent security review of new defense rules',
        'Implement temporary additional monitoring and manual review processes',
        'Schedule emergency security team meeting to address regression'
      ],
      createdAt: new Date(),
      acknowledged: false
    };
  }

  private determineSeverity(impactValue: number, type: 'BLOCK_RATE' | 'BYPASS_RATE' | 'PERFORMANCE'): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    switch (type) {
      case 'BLOCK_RATE':
      case 'BYPASS_RATE':
        if (impactValue >= 20) return 'CRITICAL';
        if (impactValue >= 15) return 'HIGH';
        if (impactValue >= 10) return 'MEDIUM';
        return 'LOW';
      case 'PERFORMANCE':
        if (impactValue >= 80) return 'CRITICAL';
        if (impactValue >= 60) return 'HIGH';
        if (impactValue >= 40) return 'MEDIUM';
        return 'LOW';
      default:
        return 'LOW';
    }
  }

  private generateRegressionSummary(comparison: PerformanceComparison, regressionTest: RegressionTest): RegressionSummary {
    const regressionDetected = comparison.regressionDetected;
    
    let severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'NONE';
    if (regressionDetected) {
      const maxImpact = Math.max(
        Math.abs(comparison.blockRateDiff),
        Math.abs(comparison.bypassRateDiff),
        Math.abs(comparison.falsePositiveRateDiff)
      );
      severity = this.determineSeverity(maxImpact, 'BLOCK_RATE');
    }

    const keyFindings: string[] = [];
    const criticalIssues: string[] = [];

    if (comparison.blockRateDiff < -5) {
      keyFindings.push(`Block rate decreased by ${Math.abs(comparison.blockRateDiff).toFixed(1)}%`);
      if (comparison.blockRateDiff < -15) {
        criticalIssues.push('Significant decrease in attack blocking capability');
      }
    }

    if (comparison.bypassRateDiff > 5) {
      keyFindings.push(`Bypass rate increased by ${comparison.bypassRateDiff.toFixed(1)}%`);
      if (comparison.bypassRateDiff > 15) {
        criticalIssues.push('Major increase in successful attack bypasses');
      }
    }

    if (regressionTest.affectedAttacks.length > 0) {
      keyFindings.push(`${regressionTest.affectedAttacks.length} attacks now bypass defenses`);
      if (regressionTest.affectedAttacks.length > 10) {
        criticalIssues.push('Large number of previously blocked attacks now succeed');
      }
    }

    return {
      regressionDetected,
      severity,
      overallImpact: comparison.summary,
      keyFindings,
      criticalIssues
    };
  }

  private generateDetailedComparison(
    previousDefense: DefenseVersion,
    currentDefense: DefenseVersion,
    comparison: PerformanceComparison
  ): DetailedComparison {
    return {
      beforeMetrics: previousDefense.performance,
      afterMetrics: currentDefense.performance,
      changes: {
        blockRateChange: comparison.blockRateDiff,
        bypassRateChange: comparison.bypassRateDiff,
        falsePositiveRateChange: comparison.falsePositiveRateDiff,
        processingTimeChange: comparison.processingTimeDiff,
        throughputChange: comparison.throughputDiff,
        overallImpactScore: Math.abs(comparison.blockRateDiff) + Math.abs(comparison.bypassRateDiff)
      },
      statisticalSignificance: Math.abs(comparison.blockRateDiff) > 5 || Math.abs(comparison.bypassRateDiff) > 5,
      confidenceLevel: 0.95 // Assume 95% confidence for now
    };
  }

  private analyzeAffectedAttacks(regressionTest: RegressionTest): AttackRegressionDetail[] {
    const details: AttackRegressionDetail[] = [];

    for (const attackId of regressionTest.affectedAttacks) {
      const result = regressionTest.results.find(r => r.attackId === attackId);
      if (!result) continue;

      const currentResult = result.firewallResponse.decision === 'BLOCK' ? 'BLOCKED' : 
                           result.firewallResponse.decision === 'FLAG' ? 'FLAGGED' : 'ALLOWED';

      details.push({
        attackId,
        attackType: result.firewallResponse.attackCategory.type,
        previousResult: 'BLOCKED', // Assume it was blocked before since it's in affected attacks
        currentResult,
        regressionType: currentResult === 'ALLOWED' ? 'NEW_BYPASS' : 'REDUCED_CONFIDENCE',
        impactDescription: currentResult === 'ALLOWED' ? 
          'Attack now bypasses all defenses' : 
          'Attack detection confidence reduced'
      });
    }

    return details;
  }

  private generateRecommendations(
    summary: RegressionSummary,
    comparison: DetailedComparison,
    affectedAttacks: AttackRegressionDetail[]
  ): RecommendationSection[] {
    const recommendations: RecommendationSection[] = [];

    // Immediate actions for critical issues
    if (summary.severity === 'CRITICAL' || summary.criticalIssues.length > 0) {
      recommendations.push({
        category: 'IMMEDIATE_ACTION',
        priority: 'HIGH',
        recommendations: [
          'Consider emergency rollback to previous defense version',
          'Implement additional manual review processes',
          'Increase monitoring frequency for attack detection',
          'Alert security team of critical regression'
        ],
        estimatedEffort: '1-2 hours'
      });
    }

    // Rule adjustments based on affected attacks
    if (affectedAttacks.length > 0) {
      const attackTypes = [...new Set(affectedAttacks.map(a => a.attackType))];
      recommendations.push({
        category: 'RULE_ADJUSTMENT',
        priority: summary.severity === 'CRITICAL' ? 'HIGH' : 'MEDIUM',
        recommendations: [
          `Review and strengthen rules for ${attackTypes.join(', ')} attacks`,
          'Analyze bypass patterns in affected attacks',
          'Update detection patterns based on new attack techniques',
          'Test rule changes against full attack dataset before deployment'
        ],
        estimatedEffort: '4-8 hours'
      });
    }

    // Monitoring recommendations
    recommendations.push({
      category: 'MONITORING',
      priority: 'MEDIUM',
      recommendations: [
        'Increase regression testing frequency',
        'Set up automated alerts for performance degradation',
        'Monitor trust score changes more closely',
        'Implement continuous attack simulation'
      ],
      estimatedEffort: '2-4 hours'
    });

    // Rollback consideration
    if (summary.severity === 'HIGH' || summary.severity === 'CRITICAL') {
      recommendations.push({
        category: 'ROLLBACK',
        priority: 'HIGH',
        recommendations: [
          'Evaluate rollback to previous stable version',
          'Prepare rollback procedure and timeline',
          'Identify minimum viable fixes vs full rollback',
          'Plan communication strategy for rollback decision'
        ],
        estimatedEffort: '1-3 hours'
      });
    }

    return recommendations;
  }

  private async storeAlert(alert: RegressionAlert): Promise<void> {
    await this.database.executeQuery(
      `INSERT INTO regression_alerts 
       (id, defense_version, previous_version, severity, alert_type, message, 
        affected_attacks, performance_impact, remediation_recommendations, created_at, acknowledged) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        alert.id,
        alert.defenseVersion,
        alert.previousVersion,
        alert.severity,
        alert.alertType,
        alert.message,
        JSON.stringify(alert.affectedAttacks),
        JSON.stringify(alert.performanceImpact),
        JSON.stringify(alert.remediationRecommendations),
        alert.createdAt.toISOString(),
        alert.acknowledged ? 1 : 0
      ]
    );
  }

  private async storeReport(report: RegressionReport): Promise<void> {
    await this.database.executeQuery(
      `INSERT INTO regression_reports 
       (id, title, defense_version, previous_version, generated_at, summary, 
        detailed_comparison, affected_attacks, recommendations, export_formats) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        report.id,
        report.title,
        report.defenseVersion,
        report.previousVersion,
        report.generatedAt.toISOString(),
        JSON.stringify(report.summary),
        JSON.stringify(report.detailedComparison),
        JSON.stringify(report.affectedAttacks),
        JSON.stringify(report.recommendations),
        JSON.stringify(report.exportFormats)
      ]
    );
  }

  private async logAlertGeneration(alert: RegressionAlert): Promise<void> {
    const logEntry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      eventType: 'DEFENSE_UPDATED',
      data: {
        defenseVersion: alert.defenseVersion,
        trustScoreChange: alert.severity === 'CRITICAL' ? -20 : alert.severity === 'HIGH' ? -10 : -5
      },
      metadata: {
        processingTime: 0
      }
    };

    await this.database.insertLogEntry(logEntry);
  }

  private parseAlertFromRow(row: any): RegressionAlert {
    return {
      id: row.id,
      defenseVersion: row.defense_version,
      previousVersion: row.previous_version,
      severity: row.severity,
      alertType: row.alert_type,
      message: row.message,
      affectedAttacks: JSON.parse(row.affected_attacks),
      performanceImpact: JSON.parse(row.performance_impact),
      remediationRecommendations: JSON.parse(row.remediation_recommendations),
      createdAt: new Date(row.created_at),
      acknowledged: row.acknowledged === 1
    };
  }

  private parseReportFromRow(row: any): RegressionReport {
    return {
      id: row.id,
      title: row.title,
      defenseVersion: row.defense_version,
      previousVersion: row.previous_version,
      generatedAt: new Date(row.generated_at),
      summary: JSON.parse(row.summary),
      detailedComparison: JSON.parse(row.detailed_comparison),
      affectedAttacks: JSON.parse(row.affected_attacks),
      recommendations: JSON.parse(row.recommendations),
      exportFormats: JSON.parse(row.export_formats)
    };
  }

  private exportReportAsCSV(report: RegressionReport): string {
    const lines: string[] = [];
    
    // Header
    lines.push('Report Title,Defense Version,Previous Version,Generated At,Regression Detected,Severity');
    lines.push(`"${report.title}","${report.defenseVersion}","${report.previousVersion}","${report.generatedAt.toISOString()}","${report.summary.regressionDetected}","${report.summary.severity}"`);
    
    lines.push('');
    lines.push('Key Findings');
    report.summary.keyFindings.forEach(finding => {
      lines.push(`"${finding}"`);
    });
    
    lines.push('');
    lines.push('Critical Issues');
    report.summary.criticalIssues.forEach(issue => {
      lines.push(`"${issue}"`);
    });
    
    lines.push('');
    lines.push('Performance Changes');
    lines.push('Metric,Before,After,Change');
    lines.push(`Block Rate,${report.detailedComparison.beforeMetrics.blockRate},${report.detailedComparison.afterMetrics.blockRate},${report.detailedComparison.changes.blockRateChange}`);
    lines.push(`Bypass Rate,${report.detailedComparison.beforeMetrics.bypassRate},${report.detailedComparison.afterMetrics.bypassRate},${report.detailedComparison.changes.bypassRateChange}`);
    lines.push(`False Positive Rate,${report.detailedComparison.beforeMetrics.falsePositiveRate},${report.detailedComparison.afterMetrics.falsePositiveRate},${report.detailedComparison.changes.falsePositiveRateChange}`);
    
    return lines.join('\n');
  }

  private exportReportAsHTML(report: RegressionReport): string {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>${report.title}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 15px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #fbc02d; font-weight: bold; }
        .low { color: #388e3c; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .recommendation { background-color: #e3f2fd; padding: 10px; margin: 5px 0; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>${report.title}</h1>
        <p><strong>Generated:</strong> ${report.generatedAt.toISOString()}</p>
        <p><strong>Versions:</strong> ${report.previousVersion} → ${report.defenseVersion}</p>
        <p><strong>Regression Detected:</strong> <span class="${report.summary.severity.toLowerCase()}">${report.summary.regressionDetected ? 'YES' : 'NO'}</span></p>
        <p><strong>Severity:</strong> <span class="${report.summary.severity.toLowerCase()}">${report.summary.severity}</span></p>
    </div>

    <div class="section">
        <h2>Summary</h2>
        <p>${report.summary.overallImpact}</p>
        
        <h3>Key Findings</h3>
        <ul>
            ${report.summary.keyFindings.map(finding => `<li>${finding}</li>`).join('')}
        </ul>
        
        ${report.summary.criticalIssues.length > 0 ? `
        <h3>Critical Issues</h3>
        <ul>
            ${report.summary.criticalIssues.map(issue => `<li class="critical">${issue}</li>`).join('')}
        </ul>
        ` : ''}
    </div>

    <div class="section">
        <h2>Performance Comparison</h2>
        <table>
            <tr><th>Metric</th><th>Before</th><th>After</th><th>Change</th></tr>
            <tr><td>Block Rate</td><td>${report.detailedComparison.beforeMetrics.blockRate}%</td><td>${report.detailedComparison.afterMetrics.blockRate}%</td><td>${report.detailedComparison.changes.blockRateChange > 0 ? '+' : ''}${report.detailedComparison.changes.blockRateChange.toFixed(1)}%</td></tr>
            <tr><td>Bypass Rate</td><td>${report.detailedComparison.beforeMetrics.bypassRate}%</td><td>${report.detailedComparison.afterMetrics.bypassRate}%</td><td>${report.detailedComparison.changes.bypassRateChange > 0 ? '+' : ''}${report.detailedComparison.changes.bypassRateChange.toFixed(1)}%</td></tr>
            <tr><td>False Positive Rate</td><td>${report.detailedComparison.beforeMetrics.falsePositiveRate}%</td><td>${report.detailedComparison.afterMetrics.falsePositiveRate}%</td><td>${report.detailedComparison.changes.falsePositiveRateChange > 0 ? '+' : ''}${report.detailedComparison.changes.falsePositiveRateChange.toFixed(1)}%</td></tr>
        </table>
    </div>

    <div class="section">
        <h2>Recommendations</h2>
        ${report.recommendations.map(section => `
            <div class="recommendation">
                <h3>${section.category.replace('_', ' ')} (${section.priority} Priority)</h3>
                <p><strong>Estimated Effort:</strong> ${section.estimatedEffort}</p>
                <ul>
                    ${section.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
        `).join('')}
    </div>
</body>
</html>`;
  }
}