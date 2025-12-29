/**
 * Defense Manager
 * Orchestrates defense updates and automated regression testing
 */

import { DefenseVersioningService } from './defense-versioning';
import { FirewallService } from '../api/firewall';
import { AttackDatasetManager } from '../data/attack-dataset';
import { RegressionAlertingService } from './regression-alerting';
import { DefenseVersion, SecurityRule, Attack, RegressionTest, AuditLogEntry, RegressionAlert, RegressionReport } from '../types/core';
import { SQLiteDatabase } from '../data/database';
import { v4 as uuidv4 } from 'uuid';

export interface DefenseManager {
  updateDefenseRules(rules: SecurityRule[], description?: string): Promise<DefenseUpdateResult>;
  scheduleRegressionTest(defenseVersion: string, datasetId?: string): Promise<RegressionTest>;
  getDefenseStatus(): Promise<DefenseStatus>;
  rollbackToVersion(version: string): Promise<DefenseVersion>;
  getActiveRegressionAlerts(): Promise<RegressionAlert[]>;
  generateRegressionReport(currentVersion: string, previousVersion: string): Promise<RegressionReport>;
  acknowledgeRegressionAlert(alertId: string): Promise<void>;
}

export interface DefenseUpdateResult {
  newVersion: DefenseVersion;
  regressionTest?: RegressionTest;
  regressionAlerts: RegressionAlert[];
  rollbackRecommended: boolean;
  updateSummary: string;
}

export interface DefenseStatus {
  currentVersion: DefenseVersion | null;
  recentVersions: DefenseVersion[];
  pendingRegressionTests: number;
  criticalRegressions: number;
  overallHealth: 'HEALTHY' | 'WARNING' | 'CRITICAL';
}

export class DefenseManagementService implements DefenseManager {
  private versioningService: DefenseVersioningService;
  private firewallService: FirewallService;
  private datasetService: AttackDatasetManager;
  private alertingService: RegressionAlertingService;
  private database: SQLiteDatabase;

  constructor(
    versioningService?: DefenseVersioningService,
    firewallService?: FirewallService,
    datasetService?: AttackDatasetManager,
    alertingService?: RegressionAlertingService,
    database?: SQLiteDatabase
  ) {
    this.database = database || new SQLiteDatabase();
    this.versioningService = versioningService || new DefenseVersioningService(this.database);
    this.firewallService = firewallService || new FirewallService(this.database);
    this.datasetService = datasetService || new AttackDatasetManager(this.database);
    this.alertingService = alertingService || new RegressionAlertingService(this.database, this.versioningService);
  }

  async initialize(): Promise<void> {
    await this.versioningService.initialize();
    await this.firewallService.initialize();
    await this.alertingService.initialize();
    // AttackDatasetManager doesn't have initialize method
  }

  async updateDefenseRules(rules: SecurityRule[], description?: string): Promise<DefenseUpdateResult> {
    // Get current version for comparison
    const currentVersion = await this.versioningService.getCurrentDefenseVersion();
    
    // Deploy new defense version
    const newVersion = await this.versioningService.deployDefenseVersion(rules, description);
    
    // Log the defense update
    await this.logDefenseUpdate(newVersion, description);

    // Get attack dataset for regression testing
    const datasets = await this.datasetService.listDatasets();
    let regressionTest: RegressionTest | undefined;
    let regressionAlerts: RegressionAlert[] = [];
    let rollbackRecommended = false;

    if (datasets.length > 0) {
      // Use the most recent dataset for regression testing
      const latestDataset = datasets[0];
      
      try {
        regressionTest = await this.scheduleRegressionTest(newVersion.version, latestDataset.id);
        
        // Generate regression alerts if there's a previous version to compare against
        if (currentVersion) {
          regressionAlerts = await this.alertingService.analyzeRegression(
            newVersion.version,
            currentVersion.version,
            regressionTest
          );
          
          // Recommend rollback if there are critical alerts or many affected attacks
          rollbackRecommended = regressionAlerts.some(alert => alert.severity === 'CRITICAL') ||
                               regressionTest.affectedAttacks.length > 5;
        }
      } catch (error) {
        console.error('Failed to run regression test:', error);
      }
    }

    const updateSummary = this.generateUpdateSummary(newVersion, regressionTest, regressionAlerts, rollbackRecommended);

    return {
      newVersion,
      regressionTest,
      regressionAlerts,
      rollbackRecommended,
      updateSummary
    };
  }

  async scheduleRegressionTest(defenseVersion: string, datasetId?: string): Promise<RegressionTest> {
    // Get the dataset to use for testing
    let attackDataset: Attack[] = [];
    
    if (datasetId) {
      const dataset = await this.datasetService.getDataset(datasetId);
      if (dataset) {
        attackDataset = dataset.attacks;
      }
    } else {
      // Use a default set of attacks or the most recent dataset
      const datasets = await this.datasetService.listDatasets();
      if (datasets.length > 0) {
        attackDataset = datasets[0].attacks;
      }
    }

    if (attackDataset.length === 0) {
      throw new Error('No attack dataset available for regression testing');
    }

    // Trigger the regression test
    const regressionTest = await this.versioningService.triggerRegressionTest(defenseVersion, attackDataset);

    // Log the regression test
    await this.logRegressionTest(regressionTest);

    return regressionTest;
  }

  async getDefenseStatus(): Promise<DefenseStatus> {
    const currentVersion = await this.versioningService.getCurrentDefenseVersion();
    const recentVersions = (await this.versioningService.listDefenseVersions()).slice(0, 5);
    
    // Count regressions
    let criticalRegressions = 0;
    let pendingRegressionTests = 0;

    for (const version of recentVersions) {
      if (version.regressionStatus === 'CRITICAL') {
        criticalRegressions++;
      }
      
      // Check if there are pending regression tests (simplified check)
      const regressionTests = await this.versioningService.getRegressionTestResults(version.version);
      if (regressionTests.length === 0) {
        pendingRegressionTests++;
      }
    }

    // Determine overall health
    let overallHealth: 'HEALTHY' | 'WARNING' | 'CRITICAL' = 'HEALTHY';
    if (criticalRegressions > 0) {
      overallHealth = 'CRITICAL';
    } else if (currentVersion?.regressionStatus === 'DETECTED' || pendingRegressionTests > 2) {
      overallHealth = 'WARNING';
    }

    return {
      currentVersion,
      recentVersions,
      pendingRegressionTests,
      criticalRegressions,
      overallHealth
    };
  }

  async rollbackToVersion(version: string): Promise<DefenseVersion> {
    const targetVersion = await this.versioningService.getDefenseVersion(version);
    if (!targetVersion) {
      throw new Error(`Defense version ${version} not found`);
    }

    // Deploy the target version as a new version (rollback)
    const rolledBackVersion = await this.versioningService.deployDefenseVersion(
      targetVersion.rules,
      `Rollback to version ${version}`
    );

    // Log the rollback
    await this.logDefenseRollback(version, rolledBackVersion.version);

    return rolledBackVersion;
  }

  private async logDefenseUpdate(version: DefenseVersion, description?: string): Promise<void> {
    const logEntry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      eventType: 'DEFENSE_UPDATED',
      data: {
        defenseVersion: version.version
      },
      metadata: {
        processingTime: 0
      }
    };

    await this.database.insertLogEntry(logEntry);
  }

  private async logRegressionTest(regressionTest: RegressionTest): Promise<void> {
    const logEntry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      eventType: 'DEFENSE_UPDATED', // Using existing event type
      data: {
        defenseVersion: regressionTest.defenseVersion,
        // Store regression info in a way that fits the existing schema
        trustScoreChange: regressionTest.regressionDetected ? -10 : 0
      },
      metadata: {
        processingTime: 0
      }
    };

    await this.database.insertLogEntry(logEntry);
  }

  private async logDefenseRollback(fromVersion: string, toVersion: string): Promise<void> {
    const logEntry: AuditLogEntry = {
      id: uuidv4(),
      timestamp: new Date(),
      eventType: 'DEFENSE_UPDATED',
      data: {
        defenseVersion: toVersion,
        // Store rollback info in a way that fits the existing schema
        trustScoreChange: -5 // Indicate rollback with negative score change
      },
      metadata: {
        processingTime: 0
      }
    };

    await this.database.insertLogEntry(logEntry);
  }

  private generateUpdateSummary(
    version: DefenseVersion, 
    regressionTest?: RegressionTest, 
    regressionAlerts?: RegressionAlert[],
    rollbackRecommended?: boolean
  ): string {
    let summary = `Defense version ${version.version} deployed with ${version.rules.length} rules.`;
    
    if (regressionTest) {
      if (regressionTest.regressionDetected) {
        summary += ` REGRESSION DETECTED: ${regressionTest.affectedAttacks.length} attacks now bypass defenses.`;
        
        // Add alert information
        if (regressionAlerts && regressionAlerts.length > 0) {
          const criticalAlerts = regressionAlerts.filter(a => a.severity === 'CRITICAL').length;
          const highAlerts = regressionAlerts.filter(a => a.severity === 'HIGH').length;
          
          if (criticalAlerts > 0) {
            summary += ` ${criticalAlerts} CRITICAL alert(s) generated.`;
          }
          if (highAlerts > 0) {
            summary += ` ${highAlerts} HIGH severity alert(s) generated.`;
          }
        }
        
        if (rollbackRecommended) {
          summary += ' ROLLBACK RECOMMENDED due to significant regression.';
        }
      } else {
        summary += ` Regression test passed: no performance degradation detected.`;
      }
    } else {
      summary += ' No regression test performed - no attack dataset available.';
    }

    return summary;
  }

  // Method to get performance comparison between versions
  async getPerformanceComparison(version1: string, version2: string) {
    return this.versioningService.compareDefensePerformance(version1, version2);
  }

  // Method to update performance metrics for a version
  async updateVersionPerformance(version: string, metrics: any) {
    return this.versioningService.updatePerformanceMetrics(version, metrics);
  }

  async getActiveRegressionAlerts(): Promise<RegressionAlert[]> {
    return await this.alertingService.getActiveAlerts();
  }

  async generateRegressionReport(currentVersion: string, previousVersion: string): Promise<RegressionReport> {
    // Get the regression test for the current version
    const regressionTests = await this.versioningService.getRegressionTestResults(currentVersion);
    
    if (regressionTests.length === 0) {
      throw new Error(`No regression test found for version ${currentVersion}`);
    }

    // Use the most recent regression test
    const regressionTest = regressionTests[0];
    
    return await this.alertingService.generateRegressionReport(
      currentVersion,
      previousVersion,
      regressionTest
    );
  }

  async acknowledgeRegressionAlert(alertId: string): Promise<void> {
    await this.alertingService.acknowledgeAlert(alertId);
  }
}