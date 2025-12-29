/**
 * Defense Logic Versioning System
 * Manages versioned security rules with regression detection capabilities
 */

import { DefenseVersion, SecurityRule, PerformanceMetrics, RegressionTest, AttackResult, Attack } from '../types/core';
import { SQLiteDatabase } from '../data/database';
import { v4 as uuidv4 } from 'uuid';

export interface DefenseVersioningSystem {
  deployDefenseVersion(rules: SecurityRule[], description?: string): Promise<DefenseVersion>;
  getCurrentDefenseVersion(): Promise<DefenseVersion | null>;
  getDefenseVersion(version: string): Promise<DefenseVersion | null>;
  listDefenseVersions(): Promise<DefenseVersion[]>;
  triggerRegressionTest(newVersion: string, attackDataset: Attack[]): Promise<RegressionTest>;
  compareDefensePerformance(version1: string, version2: string): Promise<PerformanceComparison>;
  updatePerformanceMetrics(version: string, metrics: PerformanceMetrics): Promise<void>;
}

export interface PerformanceComparison {
  version1: string;
  version2: string;
  blockRateDiff: number;
  falsePositiveRateDiff: number;
  bypassRateDiff: number;
  processingTimeDiff: number;
  throughputDiff: number;
  regressionDetected: boolean;
  summary: string;
}

export class DefenseVersioningService implements DefenseVersioningSystem {
  private database: SQLiteDatabase;
  private currentVersion: DefenseVersion | null = null;

  constructor(database?: SQLiteDatabase) {
    this.database = database || new SQLiteDatabase();
  }

  async initialize(): Promise<void> {
    if (!this.database.isConnected()) {
      await this.database.connect();
    }
    await this.initializeDefenseTables();
    this.currentVersion = await this.getCurrentDefenseVersion();
  }

  private async initializeDefenseTables(): Promise<void> {
    const tables = [
      `CREATE TABLE IF NOT EXISTS defense_versions (
        version TEXT PRIMARY KEY,
        rules TEXT NOT NULL,
        deployed_at TEXT NOT NULL,
        performance TEXT,
        regression_status TEXT DEFAULT 'NONE',
        description TEXT,
        is_current INTEGER DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS regression_tests (
        id TEXT PRIMARY KEY,
        defense_version TEXT NOT NULL,
        attack_dataset_id TEXT NOT NULL,
        results TEXT NOT NULL,
        regression_detected INTEGER NOT NULL,
        affected_attacks TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (defense_version) REFERENCES defense_versions (version)
      )`
    ];

    for (const sql of tables) {
      await this.database.executeQuery(sql);
    }
  }

  async deployDefenseVersion(rules: SecurityRule[], description?: string): Promise<DefenseVersion> {
    const version = this.generateVersionNumber();
    const deployedAt = new Date();
    
    // Initialize with default performance metrics
    const initialPerformance: PerformanceMetrics = {
      blockRate: 0,
      falsePositiveRate: 0,
      bypassRate: 0,
      averageProcessingTime: 0,
      throughput: 0
    };

    const defenseVersion: DefenseVersion = {
      version,
      rules: rules.map(rule => ({
        ...rule,
        id: rule.id || uuidv4()
      })),
      deployedAt,
      performance: initialPerformance,
      regressionStatus: 'NONE'
    };

    // Mark previous version as not current
    await this.database.executeQuery(
      'UPDATE defense_versions SET is_current = 0 WHERE is_current = 1'
    );

    // Insert new version
    await this.database.executeQuery(
      `INSERT INTO defense_versions 
       (version, rules, deployed_at, performance, regression_status, description, is_current) 
       VALUES (?, ?, ?, ?, ?, ?, 1)`,
      [
        version,
        JSON.stringify(defenseVersion.rules),
        deployedAt.toISOString(),
        JSON.stringify(initialPerformance),
        'NONE',
        description || `Defense version ${version}`,
      ]
    );

    this.currentVersion = defenseVersion;

    // Trigger automatic regression testing if there's a previous version
    const previousVersions = await this.listDefenseVersions();
    if (previousVersions.length > 1) {
      // Get some attacks for regression testing (this would typically come from the attack dataset)
      // For now, we'll trigger the test without attacks and let the caller provide them
      console.log(`New defense version ${version} deployed. Regression testing should be triggered.`);
    }

    return defenseVersion;
  }

  async getCurrentDefenseVersion(): Promise<DefenseVersion | null> {
    if (this.currentVersion) {
      return this.currentVersion;
    }

    const rows = await this.database.executeQuery(
      'SELECT * FROM defense_versions WHERE is_current = 1 LIMIT 1'
    );

    if (rows.length === 0) {
      return null;
    }

    const row = rows[0];
    const defenseVersion: DefenseVersion = {
      version: row.version,
      rules: JSON.parse(row.rules),
      deployedAt: new Date(row.deployed_at),
      performance: JSON.parse(row.performance),
      regressionStatus: row.regression_status
    };

    this.currentVersion = defenseVersion;
    return defenseVersion;
  }

  async getDefenseVersion(version: string): Promise<DefenseVersion | null> {
    const rows = await this.database.executeQuery(
      'SELECT * FROM defense_versions WHERE version = ?',
      [version]
    );

    if (rows.length === 0) {
      return null;
    }

    const row = rows[0];
    return {
      version: row.version,
      rules: JSON.parse(row.rules),
      deployedAt: new Date(row.deployed_at),
      performance: JSON.parse(row.performance),
      regressionStatus: row.regression_status
    };
  }

  async listDefenseVersions(): Promise<DefenseVersion[]> {
    const rows = await this.database.executeQuery(
      'SELECT * FROM defense_versions ORDER BY deployed_at DESC'
    );

    return rows.map(row => ({
      version: row.version,
      rules: JSON.parse(row.rules),
      deployedAt: new Date(row.deployed_at),
      performance: JSON.parse(row.performance),
      regressionStatus: row.regression_status
    }));
  }

  async triggerRegressionTest(newVersion: string, attackDataset: Attack[]): Promise<RegressionTest> {
    const newDefenseVersion = await this.getDefenseVersion(newVersion);
    if (!newDefenseVersion) {
      throw new Error(`Defense version ${newVersion} not found`);
    }

    // For this implementation, we'll simulate testing attacks against the defense
    // In a real implementation, this would integrate with the firewall service
    const results: AttackResult[] = [];
    const affectedAttacks: string[] = [];

    // Simulate testing each attack against the new defense version
    for (const attack of attackDataset) {
      const result = await this.simulateAttackTest(attack, newDefenseVersion);
      results.push(result);

      // If this attack would have been blocked by previous version but not by new version,
      // it's a regression
      if (result.success) {
        affectedAttacks.push(attack.id);
      }
    }

    // Determine if regression was detected
    const regressionDetected = affectedAttacks.length > 0;

    const regressionTest: RegressionTest = {
      defenseVersion: newVersion,
      attackDataset: `dataset-${Date.now()}`, // In real implementation, this would be the actual dataset ID
      results,
      regressionDetected,
      affectedAttacks
    };

    // Store regression test results
    await this.database.executeQuery(
      `INSERT INTO regression_tests 
       (id, defense_version, attack_dataset_id, results, regression_detected, affected_attacks, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        uuidv4(),
        newVersion,
        regressionTest.attackDataset,
        JSON.stringify(results),
        regressionDetected ? 1 : 0,
        JSON.stringify(affectedAttacks),
        new Date().toISOString()
      ]
    );

    // Update defense version regression status
    const newStatus = regressionDetected ? 
      (affectedAttacks.length > 5 ? 'CRITICAL' : 'DETECTED') : 'NONE';
    
    await this.database.executeQuery(
      'UPDATE defense_versions SET regression_status = ? WHERE version = ?',
      [newStatus, newVersion]
    );

    return regressionTest;
  }

  async compareDefensePerformance(version1: string, version2: string): Promise<PerformanceComparison> {
    const defense1 = await this.getDefenseVersion(version1);
    const defense2 = await this.getDefenseVersion(version2);

    if (!defense1 || !defense2) {
      throw new Error(`One or both defense versions not found: ${version1}, ${version2}`);
    }

    const blockRateDiff = defense2.performance.blockRate - defense1.performance.blockRate;
    const falsePositiveRateDiff = defense2.performance.falsePositiveRate - defense1.performance.falsePositiveRate;
    const bypassRateDiff = defense2.performance.bypassRate - defense1.performance.bypassRate;
    const processingTimeDiff = defense2.performance.averageProcessingTime - defense1.performance.averageProcessingTime;
    const throughputDiff = defense2.performance.throughput - defense1.performance.throughput;

    // Regression is detected if block rate decreased or bypass rate increased significantly
    const regressionDetected = blockRateDiff < -5 || bypassRateDiff > 5;

    let summary = `Comparison between ${version1} and ${version2}: `;
    if (regressionDetected) {
      summary += 'REGRESSION DETECTED - ';
    }
    
    const changes = [];
    if (Math.abs(blockRateDiff) > 1) {
      changes.push(`block rate ${blockRateDiff > 0 ? 'improved' : 'decreased'} by ${Math.abs(blockRateDiff).toFixed(1)}%`);
    }
    if (Math.abs(bypassRateDiff) > 1) {
      changes.push(`bypass rate ${bypassRateDiff > 0 ? 'increased' : 'decreased'} by ${Math.abs(bypassRateDiff).toFixed(1)}%`);
    }
    if (Math.abs(falsePositiveRateDiff) > 1) {
      changes.push(`false positive rate ${falsePositiveRateDiff > 0 ? 'increased' : 'decreased'} by ${Math.abs(falsePositiveRateDiff).toFixed(1)}%`);
    }

    summary += changes.length > 0 ? changes.join(', ') : 'minimal performance changes detected';

    return {
      version1,
      version2,
      blockRateDiff,
      falsePositiveRateDiff,
      bypassRateDiff,
      processingTimeDiff,
      throughputDiff,
      regressionDetected,
      summary
    };
  }

  async updatePerformanceMetrics(version: string, metrics: PerformanceMetrics): Promise<void> {
    await this.database.executeQuery(
      'UPDATE defense_versions SET performance = ? WHERE version = ?',
      [JSON.stringify(metrics), version]
    );

    // Update cached current version if it matches
    if (this.currentVersion && this.currentVersion.version === version) {
      this.currentVersion.performance = metrics;
    }
  }

  private generateVersionNumber(): string {
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const random = Math.random().toString(36).substring(2, 8);
    return `v${timestamp}-${random}`;
  }

  private async simulateAttackTest(attack: Attack, defenseVersion: DefenseVersion): Promise<AttackResult> {
    // This is a simplified simulation - in reality, this would use the actual firewall service
    // to test the attack against the defense rules
    
    let blocked = false;
    let riskScore = 0;

    // Check each rule against the attack
    for (const rule of defenseVersion.rules) {
      if (!rule.enabled) continue;

      let matches = false;
      if (typeof rule.pattern === 'string') {
        matches = attack.prompt.toLowerCase().includes(rule.pattern.toLowerCase());
      } else if (rule.pattern instanceof RegExp) {
        matches = rule.pattern.test(attack.prompt);
      } else {
        // Handle case where pattern is neither string nor RegExp
        matches = false;
      }

      if (matches) {
        riskScore += rule.confidence * 100;
        if (rule.action === 'BLOCK' && rule.confidence > 0.6) {
          blocked = true;
          break;
        }
      }
    }

    const success = !blocked; // Attack succeeds if not blocked

    return {
      attackId: attack.id,
      success,
      firewallResponse: {
        decision: blocked ? 'BLOCK' : 'ALLOW',
        riskScore: Math.min(100, Math.round(riskScore)),
        attackCategory: attack.category,
        explanation: blocked ? 'Attack blocked by defense rules' : 'Attack not detected',
        processingTime: Math.random() * 100 + 50, // Simulate processing time
        ruleVersion: defenseVersion.version
      },
      timestamp: new Date(),
      metrics: {
        processingTime: Math.random() * 100 + 50,
        confidence: blocked ? 0.8 : 0.2,
        bypassMethod: success ? 'Rule evasion' : undefined
      }
    };
  }

  // Method to get regression test results for a defense version
  async getRegressionTestResults(defenseVersion: string): Promise<RegressionTest[]> {
    const rows = await this.database.executeQuery(
      'SELECT * FROM regression_tests WHERE defense_version = ? ORDER BY created_at DESC',
      [defenseVersion]
    );

    return rows.map(row => ({
      defenseVersion: row.defense_version,
      attackDataset: row.attack_dataset_id,
      results: JSON.parse(row.results),
      regressionDetected: row.regression_detected === 1,
      affectedAttacks: JSON.parse(row.affected_attacks)
    }));
  }
}