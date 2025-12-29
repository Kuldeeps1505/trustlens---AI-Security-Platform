/**
 * Integration Test Suite - Complete Attack Lifecycle
 * Tests complete attack lifecycle from generation through detection
 * Verifies trust score updates in response to security events
 * Tests regression detection workflows with defense changes
 * Requirements: All
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { FirewallService } from '../api/firewall';
import { RedTeamEngine } from '../engines/red-team';
import { TrustScoreEngine } from '../engines/trust-score';
import { AttackDatasetManager } from '../data/attack-dataset';
import { DefenseManagementService } from '../engines/defense-manager';
import { SQLiteDatabase } from '../data/database';
import { Attack, SecurityRule, TrustScore, AttackResult } from '../types/core';
import { v4 as uuidv4 } from 'uuid';

describe('End-to-End Integration Tests', () => {
  let database: SQLiteDatabase;
  let firewallService: FirewallService;
  let redTeamEngine: RedTeamEngine;
  let trustScoreEngine: TrustScoreEngine;
  let datasetManager: AttackDatasetManager;
  let defenseManager: DefenseManagementService;

  beforeEach(async () => {
    // Use in-memory database for testing
    database = new SQLiteDatabase(':memory:');
    await database.connect();
    
    // Initialize all services
    firewallService = new FirewallService(database);
    await firewallService.initialize();
    
    redTeamEngine = new RedTeamEngine(firewallService);
    trustScoreEngine = new TrustScoreEngine();
    datasetManager = new AttackDatasetManager(database);
    defenseManager = new DefenseManagementService(undefined, undefined, undefined, undefined, database);
    await defenseManager.initialize();
  });

  afterEach(async () => {
    if (database && database.isConnected()) {
      await database.disconnect();
    }
  });

  describe('Complete Attack Lifecycle', () => {
    it('should execute complete attack lifecycle from generation through detection', async () => {
      // Step 1: Generate attacks using red team engine
      const generatedAttacks = await redTeamEngine.generateAttacks(5);
      expect(generatedAttacks).toHaveLength(5);
      
      // Verify attacks have proper structure
      for (const attack of generatedAttacks) {
        expect(attack.id).toBeDefined();
        expect(attack.prompt).toBeDefined();
        expect(attack.category).toBeDefined();
        expect(attack.generation).toBe(1);
        expect(attack.metadata).toBeDefined();
      }

      // Step 2: Store attacks in dataset
      const dataset = await datasetManager.createDataset(
        'Integration Test Dataset',
        'Dataset for end-to-end testing',
        generatedAttacks
      );
      
      expect(dataset.attacks).toHaveLength(5);
      expect(dataset.statistics.totalAttacks).toBe(5);

      // Step 3: Test attacks against firewall
      const testResults: AttackResult[] = [];
      for (const attack of generatedAttacks) {
        const result = await redTeamEngine.testAttack(attack);
        testResults.push(result);
        
        // Verify test result structure
        expect(result.attackId).toBe(attack.id);
        expect(result.success).toBeDefined();
        expect(result.firewallResponse).toBeDefined();
        expect(result.timestamp).toBeDefined();
      }

      // Step 4: Verify firewall responses
      for (const result of testResults) {
        const response = result.firewallResponse;
        expect(['ALLOW', 'BLOCK', 'FLAG']).toContain(response.decision);
        expect(response.riskScore).toBeGreaterThanOrEqual(0);
        expect(response.riskScore).toBeLessThanOrEqual(100);
        expect(response.attackCategory).toBeDefined();
        expect(response.explanation).toBeDefined();
        expect(response.processingTime).toBeGreaterThanOrEqual(0);
      }

      // Step 5: Verify audit logging
      const auditLogs = await database.getLogEntries();
      expect(auditLogs.length).toBeGreaterThanOrEqual(5); // At least one log per attack

      // Step 6: Test attack evolution for successful attacks
      const successfulAttacks = testResults
        .filter(result => result.success)
        .map(result => generatedAttacks.find(attack => attack.id === result.attackId)!)
        .filter(attack => attack !== undefined);

      if (successfulAttacks.length > 0) {
        // Evolve successful attacks
        const mutatedAttack = await redTeamEngine.mutateAttack(
          successfulAttacks[0], 
          'SEMANTIC_REWRITE'
        );
        
        expect(mutatedAttack.id).not.toBe(successfulAttacks[0].id);
        expect(mutatedAttack.parentId).toBe(successfulAttacks[0].id);
        expect(mutatedAttack.generation).toBe(2);
        
        // Test mutated attack
        const mutatedResult = await redTeamEngine.testAttack(mutatedAttack);
        expect(mutatedResult.attackId).toBe(mutatedAttack.id);
      }

      // Step 7: Verify lineage tracking
      const evolutionMetrics = redTeamEngine.getEvolutionMetrics();
      expect(evolutionMetrics.totalAttacksGenerated).toBeGreaterThanOrEqual(5);
      expect(evolutionMetrics.totalAttacksTested).toBeGreaterThanOrEqual(5);
    });

    it('should handle attack evolution cycles with multiple generations', async () => {
      // Run evolution cycle
      const evolutionResult = await redTeamEngine.runEvolutionCycle(3, 4);
      
      expect(evolutionResult.generation).toBe(3);
      expect(evolutionResult.totalAttacks).toBe(4);
      expect(evolutionResult.successRate).toBeGreaterThanOrEqual(0);
      expect(evolutionResult.successRate).toBeLessThanOrEqual(1);
      expect(evolutionResult.averageRiskScore).toBeGreaterThanOrEqual(0);
      expect(evolutionResult.averageRiskScore).toBeLessThanOrEqual(100);

      // Verify evolution metrics
      const metrics = redTeamEngine.getEvolutionMetrics();
      expect(metrics.totalGenerations).toBe(3);
      expect(metrics.totalAttacksGenerated).toBeGreaterThan(0);
      expect(metrics.totalAttacksTested).toBeGreaterThan(0);

      // Verify successful attacks are tracked
      const successfulAttacks = redTeamEngine.getSuccessfulAttacks();
      expect(Array.isArray(successfulAttacks)).toBe(true);
    });
  });

  describe('Trust Score Updates', () => {
    it('should update trust score in response to security events', async () => {
      // Step 1: Calculate initial trust score
      const initialComponents = {
        blockRate: 70,
        falsePositiveRate: 10,
        bypassRate: 20,
        regressionPenalty: 0,
        explainabilityScore: 85
      };
      
      const initialScore = trustScoreEngine.calculateScore(initialComponents);
      expect(initialScore.overall).toBeGreaterThan(0);
      expect(initialScore.overall).toBeLessThanOrEqual(100);

      // Step 2: Simulate security events that should affect trust score
      const attacks = await redTeamEngine.generateAttacks(10);
      const testResults: AttackResult[] = [];
      
      for (const attack of attacks) {
        const result = await redTeamEngine.testAttack(attack);
        testResults.push(result);
      }

      // Step 3: Calculate new metrics based on test results
      const blockedCount = testResults.filter(r => r.firewallResponse.decision === 'BLOCK').length;
      const allowedCount = testResults.filter(r => r.firewallResponse.decision === 'ALLOW').length;
      const flaggedCount = testResults.filter(r => r.firewallResponse.decision === 'FLAG').length;
      
      const newBlockRate = (blockedCount / testResults.length) * 100;
      const newBypassRate = (allowedCount / testResults.length) * 100;
      
      const updatedComponents = {
        ...initialComponents,
        blockRate: newBlockRate,
        bypassRate: newBypassRate
      };

      // Step 4: Update trust score and track changes
      const updatedScore = trustScoreEngine.updateScore(initialScore, updatedComponents);
      const scoreChange = trustScoreEngine.trackScoreChange(initialScore, updatedScore);

      // Step 5: Verify trust score update
      expect(updatedScore.overall).toBeGreaterThanOrEqual(0);
      expect(updatedScore.overall).toBeLessThanOrEqual(100);
      expect(updatedScore.components.blockRate).toBe(newBlockRate);
      expect(updatedScore.components.bypassRate).toBe(newBypassRate);

      // Step 6: Verify change tracking
      expect(scoreChange.previousScore).toBe(initialScore.overall);
      expect(scoreChange.newScore).toBe(updatedScore.overall);
      expect(scoreChange.changedMetrics.length).toBeGreaterThan(0);
      expect(scoreChange.reason).toBeDefined();

      // Step 7: Check threshold alerts
      const alerts = trustScoreEngine.checkThresholds(updatedScore);
      expect(Array.isArray(alerts)).toBe(true);
      
      // If score is low, should have alerts
      if (updatedScore.overall <= 60) {
        expect(alerts.length).toBeGreaterThan(0);
        expect(alerts[0].remediationRecommendations.length).toBeGreaterThan(0);
      }
    });

    it('should provide detailed explanations for trust score changes', async () => {
      const initialScore = trustScoreEngine.calculateScore({
        blockRate: 80,
        falsePositiveRate: 5,
        bypassRate: 15,
        regressionPenalty: 0,
        explainabilityScore: 90
      });

      // Simulate degraded performance
      const degradedScore = trustScoreEngine.updateScore(initialScore, {
        blockRate: 60, // Decreased by 20
        bypassRate: 35  // Increased by 20
      });

      const change = trustScoreEngine.trackScoreChange(initialScore, degradedScore);
      
      // Verify detailed change tracking
      expect(change.changedMetrics.length).toBeGreaterThanOrEqual(2);
      
      const blockRateChange = change.changedMetrics.find(m => m.metric === 'blockRate');
      const bypassRateChange = change.changedMetrics.find(m => m.metric === 'bypassRate');
      
      expect(blockRateChange).toBeDefined();
      expect(blockRateChange!.previousValue).toBe(80);
      expect(blockRateChange!.newValue).toBe(60);
      expect(blockRateChange!.impact).toBeLessThan(0); // Negative impact
      
      expect(bypassRateChange).toBeDefined();
      expect(bypassRateChange!.previousValue).toBe(15);
      expect(bypassRateChange!.newValue).toBe(35);
      expect(bypassRateChange!.impact).toBeLessThan(0); // Negative impact

      // Verify remediation recommendations
      const recommendations = trustScoreEngine.getRemediationRecommendations(degradedScore);
      expect(recommendations.length).toBeGreaterThan(0);
      expect(recommendations.some(r => r.includes('block rate'))).toBe(true);
    });
  });

  describe('Defense Regression Detection', () => {
    it('should detect regression when defense changes weaken security', async () => {
      // Step 1: Create test attack dataset
      const attacks = await redTeamEngine.generateAttacks(5);
      const dataset = await datasetManager.createDataset(
        'Regression Test Dataset',
        'Dataset for testing defense regression',
        attacks
      );

      // Step 2: Deploy strong defense version
      const strongRules: SecurityRule[] = [
        {
          id: uuidv4(),
          name: 'Strong Injection Detection',
          pattern: 'ignore|override|bypass',
          action: 'BLOCK',
          confidence: 0.9,
          enabled: true
        },
        {
          id: uuidv4(),
          name: 'Jailbreak Detection',
          pattern: 'pretend|roleplay|assume',
          action: 'BLOCK',
          confidence: 0.8,
          enabled: true
        }
      ];

      const strongDefenseResult = await defenseManager.updateDefenseRules(
        strongRules,
        'Strong defense version'
      );

      expect(strongDefenseResult.newVersion).toBeDefined();
      expect(strongDefenseResult.regressionTest).toBeDefined();

      // Step 3: Update performance metrics for strong version
      await defenseManager.updateVersionPerformance(strongDefenseResult.newVersion.version, {
        blockRate: 85,
        falsePositiveRate: 5,
        bypassRate: 15,
        averageProcessingTime: 100,
        throughput: 10
      });

      // Step 4: Deploy weak defense version
      const weakRules: SecurityRule[] = [
        {
          id: uuidv4(),
          name: 'Weak Detection',
          pattern: 'malicious',
          action: 'FLAG',
          confidence: 0.3,
          enabled: true
        }
      ];

      const weakDefenseResult = await defenseManager.updateDefenseRules(
        weakRules,
        'Weak defense version'
      );

      // Step 5: Update performance metrics for weak version (simulate poor performance)
      await defenseManager.updateVersionPerformance(weakDefenseResult.newVersion.version, {
        blockRate: 40, // 45% decrease
        falsePositiveRate: 8,
        bypassRate: 60, // 45% increase
        averageProcessingTime: 120,
        throughput: 8
      });

      // Step 6: Check for regression detection
      expect(weakDefenseResult.regressionTest?.regressionDetected).toBe(true);
      expect(weakDefenseResult.rollbackRecommended).toBe(true);

      // Step 7: Verify regression alerts
      const alerts = await defenseManager.getActiveRegressionAlerts();
      expect(alerts.length).toBeGreaterThan(0);
      
      const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL');
      expect(criticalAlerts.length).toBeGreaterThan(0);

      // Step 8: Generate regression report
      const report = await defenseManager.generateRegressionReport(
        weakDefenseResult.newVersion.version,
        strongDefenseResult.newVersion.version
      );

      expect(report.summary.regressionDetected).toBe(true);
      expect(report.summary.severity).toBe('CRITICAL');
      expect(report.recommendations.length).toBeGreaterThan(0);
    });

    it('should maintain defense version history and audit trails', async () => {
      // Deploy multiple defense versions
      const versions: string[] = [];
      
      for (let i = 0; i < 3; i++) {
        const rules: SecurityRule[] = [
          {
            id: uuidv4(),
            name: `Rule Set ${i + 1}`,
            pattern: `pattern${i}`,
            action: 'BLOCK',
            confidence: 0.7 + (i * 0.1),
            enabled: true
          }
        ];

        const result = await defenseManager.updateDefenseRules(
          rules,
          `Defense version ${i + 1}`
        );
        
        versions.push(result.newVersion.version);
      }

      // Verify version history
      const defenseStatus = await defenseManager.getDefenseStatus();
      expect(defenseStatus.recentVersions.length).toBeGreaterThanOrEqual(3);
      expect(defenseStatus.currentVersion).toBeDefined();

      // Verify audit trails exist for all versions
      for (const version of versions) {
        const versionDetails = defenseStatus.recentVersions.find(v => v.version === version);
        expect(versionDetails).toBeDefined();
        expect(versionDetails!.deployedAt).toBeDefined();
      }
    });
  });

  describe('System Integration Scenarios', () => {
    it('should handle concurrent operations across all components', async () => {
      // Simulate concurrent operations
      const promises = [
        // Generate attacks
        redTeamEngine.generateAttacks(3),
        
        // Update defense rules
        defenseManager.updateDefenseRules([
          {
            id: uuidv4(),
            name: 'Concurrent Test Rule',
            pattern: 'test',
            action: 'FLAG',
            confidence: 0.5,
            enabled: true
          }
        ], 'Concurrent test defense'),
        
        // Calculate trust score
        Promise.resolve(trustScoreEngine.calculateScore({
          blockRate: 75,
          falsePositiveRate: 8,
          bypassRate: 20,
          regressionPenalty: 2,
          explainabilityScore: 88
        }))
      ];

      const results = await Promise.all(promises);
      
      // Verify all operations completed successfully
      expect(results[0]).toHaveLength(3); // Attacks generated
      expect(results[1].newVersion).toBeDefined(); // Defense updated
      expect(results[2].overall).toBeGreaterThan(0); // Trust score calculated
    });

    it('should maintain data consistency across database operations', async () => {
      // Create multiple datasets
      const dataset1 = await datasetManager.createDataset(
        'Dataset 1',
        'First test dataset',
        await redTeamEngine.generateAttacks(3)
      );
      
      const dataset2 = await datasetManager.createDataset(
        'Dataset 2', 
        'Second test dataset',
        await redTeamEngine.generateAttacks(2)
      );

      // Verify datasets are stored correctly
      const allDatasets = await datasetManager.listDatasets();
      expect(allDatasets.length).toBeGreaterThanOrEqual(2);
      
      const retrievedDataset1 = await datasetManager.getDataset(dataset1.id);
      const retrievedDataset2 = await datasetManager.getDataset(dataset2.id);
      
      expect(retrievedDataset1).toBeDefined();
      expect(retrievedDataset2).toBeDefined();
      expect(retrievedDataset1!.attacks).toHaveLength(3);
      expect(retrievedDataset2!.attacks).toHaveLength(2);

      // Test cross-dataset search
      const searchResults = await datasetManager.searchAttacks({
        source: 'AI_GENERATED'
      });
      
      expect(searchResults.length).toBeGreaterThanOrEqual(5);
    });

    it('should handle error scenarios gracefully', async () => {
      // Test invalid trust score calculation
      expect(() => {
        trustScoreEngine.calculateScore({
          blockRate: -10, // Invalid
          falsePositiveRate: 5,
          bypassRate: 20,
          regressionPenalty: 0,
          explainabilityScore: 85
        });
      }).toThrow();

      // Test non-existent dataset retrieval
      const nonExistentDataset = await datasetManager.getDataset('non-existent-id');
      expect(nonExistentDataset).toBeNull();

      // Test invalid firewall request
      await expect(async () => {
        await firewallService.analyzePrompt({
          prompt: '', // Empty prompt should be invalid
          context: 'test',
          userId: 'test-user',
          sessionId: 'test-session'
        });
      }).rejects.toThrow();
    });
  });
});