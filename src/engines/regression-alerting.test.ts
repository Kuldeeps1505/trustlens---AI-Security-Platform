/**
 * Unit tests for Regression Alerting and Reporting System
 * Tests core functionality of alert generation and report creation
 */

import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { RegressionAlertingService } from './regression-alerting';
import { DefenseVersioningService } from './defense-versioning';
import { SQLiteDatabase } from '../data/database';
import { SecurityRule, Attack, AttackCategory, RegressionTest, AttackResult } from '../types/core';
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs';

describe('Regression Alerting System', () => {
  let database: SQLiteDatabase;
  let versioningService: DefenseVersioningService;
  let alertingService: RegressionAlertingService;
  const testDbPath = './test-regression-alerting.db';

  beforeAll(async () => {
    // Clean up any existing test database
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
    // Clean up test database
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

  it('should generate regression alerts when block rate decreases significantly', async () => {
    // Setup
    database = new SQLiteDatabase();
    (database as any).dbPath = testDbPath;
    await database.connect();
    
    versioningService = new DefenseVersioningService(database);
    await versioningService.initialize();
    
    alertingService = new RegressionAlertingService(database, versioningService);
    await alertingService.initialize();

    // Create two defense versions with different performance
    const rules1: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Strong Rule',
        pattern: 'malicious',
        action: 'BLOCK',
        confidence: 0.9,
        enabled: true
      }
    ];

    const rules2: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Weak Rule',
        pattern: 'suspicious',
        action: 'FLAG',
        confidence: 0.3,
        enabled: true
      }
    ];

    const version1 = await versioningService.deployDefenseVersion(rules1, 'Strong version');
    const version2 = await versioningService.deployDefenseVersion(rules2, 'Weak version');

    // Set performance metrics to simulate regression
    await versioningService.updatePerformanceMetrics(version1.version, {
      blockRate: 80,
      falsePositiveRate: 5,
      bypassRate: 20,
      averageProcessingTime: 100,
      throughput: 10
    });

    await versioningService.updatePerformanceMetrics(version2.version, {
      blockRate: 60, // 20% decrease - should trigger alert
      falsePositiveRate: 5,
      bypassRate: 40, // 20% increase - should trigger alert
      averageProcessingTime: 100,
      throughput: 10
    });

    // Create mock regression test
    const attackCategory: AttackCategory = {
      type: 'PROMPT_INJECTION',
      confidence: 0.8,
      indicators: ['malicious pattern']
    };

    const mockAttacks: Attack[] = [
      {
        id: uuidv4(),
        prompt: 'malicious prompt',
        category: attackCategory,
        generation: 1,
        metadata: {
          createdAt: new Date(),
          source: 'AI_GENERATED',
          severity: 'HIGH'
        }
      }
    ];

    const regressionTest = await versioningService.triggerRegressionTest(version2.version, mockAttacks);

    // Generate alerts
    const alerts = await alertingService.analyzeRegression(
      version2.version,
      version1.version,
      regressionTest
    );

    // Verify alerts were generated
    expect(alerts.length).toBeGreaterThan(0);
    
    // Should have block rate decrease alert
    const blockRateAlert = alerts.find(a => a.alertType === 'BLOCK_RATE_DECREASE');
    expect(blockRateAlert).toBeDefined();
    expect(blockRateAlert?.severity).toBe('CRITICAL'); // 20% decrease should be CRITICAL severity
    expect(blockRateAlert?.message).toContain('Block rate decreased by 20.0%');

    // Should have bypass rate increase alert
    const bypassRateAlert = alerts.find(a => a.alertType === 'BYPASS_RATE_INCREASE');
    expect(bypassRateAlert).toBeDefined();
    expect(bypassRateAlert?.severity).toBe('CRITICAL'); // 20% increase should be CRITICAL severity

    // Should have critical regression alert due to combined impact
    const criticalAlert = alerts.find(a => a.alertType === 'CRITICAL_REGRESSION');
    expect(criticalAlert).toBeDefined();
    expect(criticalAlert?.severity).toBe('CRITICAL');

    // Verify alerts have remediation recommendations
    for (const alert of alerts) {
      expect(alert.remediationRecommendations.length).toBeGreaterThan(0);
      expect(alert.performanceImpact).toBeDefined();
      expect(alert.createdAt).toBeInstanceOf(Date);
      expect(alert.acknowledged).toBe(false);
    }

    await database.disconnect();
  });

  it('should generate comprehensive regression report', async () => {
    // Setup
    database = new SQLiteDatabase();
    (database as any).dbPath = testDbPath;
    await database.connect();
    
    versioningService = new DefenseVersioningService(database);
    await versioningService.initialize();
    
    alertingService = new RegressionAlertingService(database, versioningService);
    await alertingService.initialize();

    // Create defense versions
    const rules1: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Test Rule 1',
        pattern: 'attack',
        action: 'BLOCK',
        confidence: 0.8,
        enabled: true
      }
    ];

    const rules2: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Test Rule 2',
        pattern: 'threat',
        action: 'BLOCK',
        confidence: 0.7,
        enabled: true
      }
    ];

    const version1 = await versioningService.deployDefenseVersion(rules1, 'Version 1');
    const version2 = await versioningService.deployDefenseVersion(rules2, 'Version 2');

    // Set performance metrics
    await versioningService.updatePerformanceMetrics(version1.version, {
      blockRate: 75,
      falsePositiveRate: 10,
      bypassRate: 25,
      averageProcessingTime: 120,
      throughput: 8
    });

    await versioningService.updatePerformanceMetrics(version2.version, {
      blockRate: 65, // 10% decrease
      falsePositiveRate: 15, // 5% increase
      bypassRate: 35, // 10% increase
      averageProcessingTime: 140, // 20ms increase
      throughput: 7 // 1 req/s decrease
    });

    // Create regression test
    const attackCategory: AttackCategory = {
      type: 'JAILBREAK',
      confidence: 0.9,
      indicators: ['jailbreak pattern']
    };

    const mockAttacks: Attack[] = [
      {
        id: uuidv4(),
        prompt: 'jailbreak attempt',
        category: attackCategory,
        generation: 1,
        metadata: {
          createdAt: new Date(),
          source: 'MANUAL',
          severity: 'MEDIUM'
        }
      }
    ];

    const regressionTest = await versioningService.triggerRegressionTest(version2.version, mockAttacks);

    // Generate report
    const report = await alertingService.generateRegressionReport(
      version2.version,
      version1.version,
      regressionTest
    );

    // Verify report structure
    expect(report.id).toBeDefined();
    expect(report.title).toContain(version1.version);
    expect(report.title).toContain(version2.version);
    expect(report.defenseVersion).toBe(version2.version);
    expect(report.previousVersion).toBe(version1.version);
    expect(report.generatedAt).toBeInstanceOf(Date);

    // Verify summary
    expect(report.summary.regressionDetected).toBe(true);
    expect(report.summary.severity).toBeDefined();
    expect(report.summary.overallImpact).toBeDefined();
    expect(report.summary.keyFindings.length).toBeGreaterThan(0);

    // Verify detailed comparison
    expect(report.detailedComparison.beforeMetrics.blockRate).toBe(75);
    expect(report.detailedComparison.afterMetrics.blockRate).toBe(65);
    expect(report.detailedComparison.changes.blockRateChange).toBe(-10);
    expect(report.detailedComparison.statisticalSignificance).toBe(true);

    // Verify recommendations
    expect(report.recommendations.length).toBeGreaterThan(0);
    const immediateActions = report.recommendations.find(r => r.category === 'IMMEDIATE_ACTION');
    const ruleAdjustments = report.recommendations.find(r => r.category === 'RULE_ADJUSTMENT');
    
    expect(immediateActions || ruleAdjustments).toBeDefined(); // At least one should exist

    // Verify export formats
    expect(report.exportFormats).toContain('JSON');
    expect(report.exportFormats).toContain('CSV');
    expect(report.exportFormats).toContain('HTML');

    await database.disconnect();
  });

  it('should acknowledge alerts correctly', async () => {
    // Setup
    database = new SQLiteDatabase();
    (database as any).dbPath = testDbPath;
    await database.connect();
    
    versioningService = new DefenseVersioningService(database);
    await versioningService.initialize();
    
    alertingService = new RegressionAlertingService(database, versioningService);
    await alertingService.initialize();

    // Create a simple regression scenario
    const rules: SecurityRule[] = [
      {
        id: uuidv4(),
        name: 'Test Rule',
        pattern: 'test',
        action: 'BLOCK',
        confidence: 0.5,
        enabled: true
      }
    ];

    const version1 = await versioningService.deployDefenseVersion(rules, 'Version 1');
    const version2 = await versioningService.deployDefenseVersion(rules, 'Version 2');

    // Set up regression scenario
    await versioningService.updatePerformanceMetrics(version1.version, {
      blockRate: 70,
      falsePositiveRate: 5,
      bypassRate: 30,
      averageProcessingTime: 100,
      throughput: 10
    });

    await versioningService.updatePerformanceMetrics(version2.version, {
      blockRate: 50, // 20% decrease - should trigger alert
      falsePositiveRate: 5,
      bypassRate: 50, // 20% increase
      averageProcessingTime: 100,
      throughput: 10
    });

    const mockAttacks: Attack[] = [
      {
        id: uuidv4(),
        prompt: 'test attack',
        category: {
          type: 'PROMPT_INJECTION',
          confidence: 0.8,
          indicators: ['test']
        },
        generation: 1,
        metadata: {
          createdAt: new Date(),
          source: 'AI_GENERATED',
          severity: 'HIGH'
        }
      }
    ];

    const regressionTest = await versioningService.triggerRegressionTest(version2.version, mockAttacks);
    const alerts = await alertingService.analyzeRegression(version2.version, version1.version, regressionTest);

    expect(alerts.length).toBeGreaterThan(0);

    // Get active alerts
    const activeAlerts = await alertingService.getActiveAlerts();
    expect(activeAlerts.length).toBe(alerts.length);
    expect(activeAlerts.every(a => !a.acknowledged)).toBe(true);

    // Acknowledge first alert
    const firstAlert = activeAlerts[0];
    await alertingService.acknowledgeAlert(firstAlert.id);

    // Verify alert was acknowledged
    const updatedActiveAlerts = await alertingService.getActiveAlerts();
    expect(updatedActiveAlerts.length).toBe(alerts.length - 1);

    await database.disconnect();
  });
});