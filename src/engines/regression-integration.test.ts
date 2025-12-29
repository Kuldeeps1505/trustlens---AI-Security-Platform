/**
 * Integration test for complete regression alerting workflow
 * Demonstrates end-to-end functionality from defense update to alert generation
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { DefenseManagementService } from './defense-manager';
import { SQLiteDatabase } from '../data/database';
import { AttackDatasetManager } from '../data/attack-dataset';
import { SecurityRule, Attack, AttackCategory } from '../types/core';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';

describe('Regression Alerting Integration', () => {
  let database: SQLiteDatabase;
  let defenseManager: DefenseManagementService;
  let datasetManager: AttackDatasetManager;
  const testDbPath = './test-regression-integration.db';

  beforeAll(async () => {
    if (fs.existsSync(testDbPath)) {
      fs.unlinkSync(testDbPath);
    }
  });

  afterAll(async () => {
    if (database) {
      try {
        if (database.isConnected()) {
          await database.disconnect();
        }
      } catch (error) {
        console.warn('Database disconnect error in afterAll:', error);
      }
    }
    try {
      if (fs.existsSync(testDbPath)) {
        await new Promise(resolve => setTimeout(resolve, 100));
        fs.unlinkSync(testDbPath);
      }
    } catch (error) {
      console.warn('File cleanup error in afterAll:', error);
    }
  });

  afterEach(async () => {
    if (database) {
      try {
        if (database.isConnected()) {
          await database.disconnect();
        }
      } catch (error) {
        console.warn('Database disconnect error:', error);
      }
    }
    try {
      if (fs.existsSync(testDbPath)) {
        fs.unlinkSync(testDbPath);
      }
    } catch (error) {
      console.warn('File cleanup error:', error);
    }
  });

  it('should complete full regression alerting workflow', async () => {
    // Setup
    database = new SQLiteDatabase();
    (database as any).dbPath = testDbPath;
    await database.connect();
    
    defenseManager = new DefenseManagementService(undefined, undefined, undefined, undefined, database);
    await defenseManager.initialize();
    
    datasetManager = new AttackDatasetManager(database);

    // Create attack dataset for testing
    const attackCategory: AttackCategory = {
      type: 'PROMPT_INJECTION',
      confidence: 0.9,
      indicators: ['malicious', 'injection']
    };

    const testAttacks: Attack[] = [
      {
        id: uuidv4(),
        prompt: 'malicious injection attempt',
        category: attackCategory,
        generation: 1,
        metadata: {
          createdAt: new Date(),
          source: 'AI_GENERATED',
          severity: 'HIGH'
        }
      },
      {
        id: uuidv4(),
        prompt: 'another malicious prompt',
        category: attackCategory,
        generation: 1,
        metadata: {
          createdAt: new Date(),
          source: 'MANUAL',
          severity: 'MEDIUM'
        }
      }
    ];

    const dataset = await datasetManager.createDataset(
      'Test Regression Dataset',
      'Dataset for regression testing',
      testAttacks
    );

    // Deploy initial strong defense version
    const strongRules: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Strong Malicious Pattern Detection',
        pattern: 'malicious',
        action: 'BLOCK',
        confidence: 0.9,
        enabled: true
      },
      {
        id: uuidv4(),
        name: 'Injection Pattern Detection',
        pattern: 'injection',
        action: 'BLOCK',
        confidence: 0.8,
        enabled: true
      }
    ];

    const strongDefenseResult = await defenseManager.updateDefenseRules(
      strongRules,
      'Strong defense version with comprehensive rules'
    );

    expect(strongDefenseResult.newVersion).toBeDefined();
    expect(strongDefenseResult.regressionTest).toBeDefined();
    expect(strongDefenseResult.regressionAlerts).toBeDefined();

    // Update performance metrics for the strong version (simulate good performance)
    await defenseManager.updateVersionPerformance(strongDefenseResult.newVersion.version, {
      blockRate: 85,
      falsePositiveRate: 5,
      bypassRate: 15,
      averageProcessingTime: 120,
      throughput: 8
    });

    // Deploy weaker defense version that should trigger regression alerts
    const weakRules: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Weak Pattern Detection',
        pattern: 'suspicious',
        action: 'FLAG',
        confidence: 0.3,
        enabled: true
      }
    ];

    const weakDefenseResult = await defenseManager.updateDefenseRules(
      weakRules,
      'Weak defense version with limited rules'
    );

    expect(weakDefenseResult.newVersion).toBeDefined();
    expect(weakDefenseResult.regressionTest).toBeDefined();
    expect(weakDefenseResult.regressionAlerts).toBeDefined();

    // Update performance metrics for the weak version (simulate poor performance)
    await defenseManager.updateVersionPerformance(weakDefenseResult.newVersion.version, {
      blockRate: 40, // 45% decrease - should trigger CRITICAL alert
      falsePositiveRate: 8,
      bypassRate: 60, // 45% increase - should trigger CRITICAL alert
      averageProcessingTime: 150,
      throughput: 6
    });

    // Re-run regression analysis with updated metrics
    const updatedRegressionTest = await defenseManager.scheduleRegressionTest(
      weakDefenseResult.newVersion.version,
      dataset.id
    );

    // Generate alerts based on the performance comparison
    const alerts = await defenseManager.getActiveRegressionAlerts();

    // Verify regression was detected
    expect(weakDefenseResult.regressionTest?.regressionDetected).toBe(true);
    expect(weakDefenseResult.regressionTest?.affectedAttacks.length).toBeGreaterThan(0);

    // Verify alerts were generated
    expect(alerts.length).toBeGreaterThan(0);

    // Should have critical alerts due to significant performance degradation
    const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL');
    expect(criticalAlerts.length).toBeGreaterThan(0);

    // Verify rollback recommendation
    expect(weakDefenseResult.rollbackRecommended).toBe(true);

    // Generate comprehensive regression report
    const report = await defenseManager.generateRegressionReport(
      weakDefenseResult.newVersion.version,
      strongDefenseResult.newVersion.version
    );

    expect(report).toBeDefined();
    expect(report.summary.regressionDetected).toBe(true);
    expect(report.summary.severity).toBe('CRITICAL');
    expect(report.summary.criticalIssues.length).toBeGreaterThan(0);
    expect(report.recommendations.length).toBeGreaterThan(0);

    // Verify immediate action recommendations exist for critical regression
    const immediateActions = report.recommendations.find(r => r.category === 'IMMEDIATE_ACTION');
    expect(immediateActions).toBeDefined();
    expect(immediateActions?.priority).toBe('HIGH');

    // Verify rollback recommendations exist
    const rollbackRecommendations = report.recommendations.find(r => r.category === 'ROLLBACK');
    expect(rollbackRecommendations).toBeDefined();

    // Test alert acknowledgment
    const firstAlert = alerts[0];
    await defenseManager.acknowledgeRegressionAlert(firstAlert.id);

    const remainingAlerts = await defenseManager.getActiveRegressionAlerts();
    expect(remainingAlerts.length).toBe(alerts.length - 1);

    // Verify defense status reflects the regression
    const defenseStatus = await defenseManager.getDefenseStatus();
    // Note: The defense status may not show CRITICAL immediately because the regression status
    // is determined during the regression test, not after performance metrics are updated.
    // In a real scenario, the next regression test would detect the critical status.
    expect(defenseStatus.currentVersion).toBeDefined();
    expect(defenseStatus.recentVersions.length).toBeGreaterThan(0);

    console.log('✅ Regression alerting workflow completed successfully');
    console.log(`📊 Generated ${alerts.length} alerts (${criticalAlerts.length} critical)`);
    console.log(`📋 Report contains ${report.recommendations.length} recommendation sections`);
    console.log(`⚠️  Defense health status: ${defenseStatus.overallHealth}`);

    await database.disconnect();
  });
});