/**
 * Benchmarking and Evaluation Pipeline
 * Implements fixed attack dataset management for benchmarking
 * Provides baseline comparison system (no-defense, simple-rule)
 * Ensures reproducible benchmark execution with identical test conditions
 * Requirements: 7.1, 7.4
 */

import { v4 as uuidv4 } from 'uuid';
import { AttackDataset, Attack, FirewallRequest, FirewallResponse, AttackResult } from '../types/core';
import { FirewallService } from '../api/firewall';
import { AttackDatasetManager } from '../data/attack-dataset';
import { SQLiteDatabase } from '../data/database';
import { BenchmarkReportGenerator, BenchmarkExporter, EvaluationMetricsCalculator } from './evaluation-metrics';

export interface BenchmarkConfiguration {
  id: string;
  name: string;
  description: string;
  attackDatasetId: string;
  attackDatasetVersion: string;
  baselineTypes: BaselineType[];
  testConditions: TestConditions;
  createdAt: Date;
}

export interface TestConditions {
  randomSeed: number;
  maxConcurrentRequests: number;
  requestTimeoutMs: number;
  retryAttempts: number;
  environmentVariables: Record<string, string>;
}

export interface BaselineType {
  name: 'no-defense' | 'simple-rule' | 'current-firewall';
  description: string;
  enabled: boolean;
}

export interface BenchmarkResult {
  id: string;
  configurationId: string;
  executedAt: Date;
  completedAt: Date;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  baselineResults: BaselineResult[];
  summary: BenchmarkSummary;
  reproducibilityHash: string; // Hash of test conditions for reproducibility verification
}

export interface BaselineResult {
  baselineType: BaselineType['name'];
  attackResults: AttackResult[];
  metrics: BaselineMetrics;
  executionTimeMs: number;
  errors: string[];
}

export interface BaselineMetrics {
  totalAttacks: number;
  blockedAttacks: number;
  flaggedAttacks: number;
  allowedAttacks: number;
  blockRate: number; // Percentage of attacks blocked
  falsePositiveRate: number; // Percentage of legitimate requests incorrectly flagged
  bypassRate: number; // Percentage of attacks that succeeded (allowed)
  averageProcessingTime: number;
  averageRiskScore: number;
}

export interface BenchmarkSummary {
  totalAttacksProcessed: number;
  totalExecutionTimeMs: number;
  baselineComparison: BaselineComparison[];
  topPerformingBaseline: BaselineType['name'];
  significantFindings: string[];
}

export interface BaselineComparison {
  baseline1: BaselineType['name'];
  baseline2: BaselineType['name'];
  blockRateDifference: number;
  bypassRateDifference: number;
  processingTimeDifference: number;
  statisticalSignificance: boolean;
}

// Simple rule-based firewall for baseline comparison
class SimpleRuleFirewall {
  async analyzePrompt(request: FirewallRequest): Promise<FirewallResponse> {
    const startTime = Date.now();
    const prompt = request.prompt.toLowerCase();
    
    // Simple keyword-based detection
    const dangerousKeywords = [
      'ignore instructions', 'ignore previous', 'jailbreak', 'bypass',
      'override', 'system:', 'admin mode', 'developer mode'
    ];
    
    let riskScore = 0;
    const indicators: string[] = [];
    
    for (const keyword of dangerousKeywords) {
      if (prompt.includes(keyword)) {
        riskScore += 25;
        indicators.push(keyword);
      }
    }
    
    riskScore = Math.min(100, riskScore);
    
    const decision = riskScore >= 50 ? 'BLOCK' : riskScore >= 25 ? 'FLAG' : 'ALLOW';
    
    return {
      decision,
      riskScore,
      attackCategory: {
        type: 'PROMPT_INJECTION',
        confidence: riskScore / 100,
        indicators
      },
      explanation: `Simple rule-based detection. Risk score: ${riskScore}`,
      processingTime: Date.now() - startTime,
      ruleVersion: 'simple-1.0.0'
    };
  }
}

// No-defense firewall that allows everything
class NoDefenseFirewall {
  async analyzePrompt(request: FirewallRequest): Promise<FirewallResponse> {
    const startTime = Date.now();
    
    return {
      decision: 'ALLOW',
      riskScore: 0,
      attackCategory: {
        type: 'PROMPT_INJECTION',
        confidence: 0,
        indicators: []
      },
      explanation: 'No defense active - all requests allowed',
      processingTime: Date.now() - startTime,
      ruleVersion: 'no-defense-1.0.0'
    };
  }
}

export interface BenchmarkExecutor {
  createConfiguration(config: Omit<BenchmarkConfiguration, 'id' | 'createdAt'>): Promise<BenchmarkConfiguration>;
  executeConfiguration(configId: string): Promise<BenchmarkResult>;
  getResult(resultId: string): Promise<BenchmarkResult | null>;
  listConfigurations(): Promise<BenchmarkConfiguration[]>;
  listResults(configId?: string): Promise<BenchmarkResult[]>;
  validateReproducibility(result1Id: string, result2Id: string): Promise<boolean>;
  generateReport(resultId: string): Promise<any>;
  exportResults(resultId: string, format: 'JSON' | 'CSV' | 'HTML' | 'PDF'): Promise<any>;
}

export class BenchmarkService implements BenchmarkExecutor {
  private database: SQLiteDatabase;
  private datasetManager: AttackDatasetManager;
  private firewallService: FirewallService;
  private simpleRuleFirewall: SimpleRuleFirewall;
  private noDefenseFirewall: NoDefenseFirewall;
  private reportGenerator: BenchmarkReportGenerator;
  private exporter: BenchmarkExporter;
  private metricsCalculator: EvaluationMetricsCalculator;

  constructor(database: SQLiteDatabase, datasetManager: AttackDatasetManager, firewallService: FirewallService) {
    this.database = database;
    this.datasetManager = datasetManager;
    this.firewallService = firewallService;
    this.simpleRuleFirewall = new SimpleRuleFirewall();
    this.noDefenseFirewall = new NoDefenseFirewall();
    this.reportGenerator = new BenchmarkReportGenerator();
    this.exporter = new BenchmarkExporter();
    this.metricsCalculator = new EvaluationMetricsCalculator();
  }

  async createConfiguration(config: Omit<BenchmarkConfiguration, 'id' | 'createdAt'>): Promise<BenchmarkConfiguration> {
    // Validate that the attack dataset exists
    const dataset = await this.datasetManager.getDataset(config.attackDatasetId, config.attackDatasetVersion);
    if (!dataset) {
      throw new Error(`Attack dataset ${config.attackDatasetId} version ${config.attackDatasetVersion} not found`);
    }

    if (dataset.attacks.length === 0) {
      throw new Error('Cannot create benchmark with empty attack dataset');
    }

    const configuration: BenchmarkConfiguration = {
      id: uuidv4(),
      createdAt: new Date(),
      ...config
    };

    await this.database.saveBenchmarkConfiguration(configuration);
    return configuration;
  }

  async executeConfiguration(configId: string): Promise<BenchmarkResult> {
    const config = await this.database.getBenchmarkConfiguration(configId);
    if (!config) {
      throw new Error(`Benchmark configuration ${configId} not found`);
    }

    const dataset = await this.datasetManager.getDataset(config.attackDatasetId, config.attackDatasetVersion);
    if (!dataset) {
      throw new Error(`Attack dataset ${config.attackDatasetId} version ${config.attackDatasetVersion} not found`);
    }

    const result: BenchmarkResult = {
      id: uuidv4(),
      configurationId: configId,
      executedAt: new Date(),
      completedAt: new Date(), // Will be updated when complete
      status: 'RUNNING',
      baselineResults: [],
      summary: {
        totalAttacksProcessed: 0,
        totalExecutionTimeMs: 0,
        baselineComparison: [],
        topPerformingBaseline: 'no-defense',
        significantFindings: []
      },
      reproducibilityHash: this.generateReproducibilityHash(config, dataset)
    };

    try {
      // Execute each enabled baseline
      for (const baselineType of config.baselineTypes.filter(b => b.enabled)) {
        const baselineResult = await this.executeBaseline(baselineType, dataset.attacks, config.testConditions);
        result.baselineResults.push(baselineResult);
      }

      // Generate summary and comparisons
      result.summary = this.generateBenchmarkSummary(result.baselineResults);
      result.status = 'COMPLETED';
      result.completedAt = new Date();

      await this.database.saveBenchmarkResult(result);
      return result;

    } catch (error) {
      result.status = 'FAILED';
      result.completedAt = new Date();
      await this.database.saveBenchmarkResult(result);
      throw error;
    }
  }

  private async executeBaseline(
    baselineType: BaselineType, 
    attacks: Attack[], 
    testConditions: TestConditions
  ): Promise<BaselineResult> {
    const startTime = Date.now();
    const attackResults: AttackResult[] = [];
    const errors: string[] = [];

    // Set random seed for reproducibility
    Math.random = this.seededRandom(testConditions.randomSeed);

    // Shuffle attacks using seeded random for consistent ordering
    const shuffledAttacks = [...attacks].sort(() => Math.random() - 0.5);

    // Select firewall implementation based on baseline type
    let firewall: { analyzePrompt(request: FirewallRequest): Promise<FirewallResponse> };
    
    switch (baselineType.name) {
      case 'no-defense':
        firewall = this.noDefenseFirewall;
        break;
      case 'simple-rule':
        firewall = this.simpleRuleFirewall;
        break;
      case 'current-firewall':
        firewall = this.firewallService;
        break;
      default:
        throw new Error(`Unknown baseline type: ${baselineType.name}`);
    }

    // Process attacks with controlled concurrency
    const semaphore = new Semaphore(testConditions.maxConcurrentRequests);
    const promises = shuffledAttacks.map(async (attack) => {
      await semaphore.acquire();
      try {
        const result = await this.processAttackWithRetry(
          attack, 
          firewall, 
          testConditions.requestTimeoutMs,
          testConditions.retryAttempts
        );
        attackResults.push(result);
      } catch (error) {
        errors.push(`Attack ${attack.id}: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        semaphore.release();
      }
    });

    await Promise.all(promises);

    const metrics = this.calculateBaselineMetrics(attackResults);
    
    return {
      baselineType: baselineType.name,
      attackResults,
      metrics,
      executionTimeMs: Date.now() - startTime,
      errors
    };
  }

  private async processAttackWithRetry(
    attack: Attack,
    firewall: { analyzePrompt(request: FirewallRequest): Promise<FirewallResponse> },
    timeoutMs: number,
    retryAttempts: number
  ): Promise<AttackResult> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= retryAttempts; attempt++) {
      try {
        const request: FirewallRequest = {
          prompt: attack.prompt,
          context: `Benchmark test for attack ${attack.id}`,
          userId: 'benchmark-system',
          sessionId: `benchmark-${Date.now()}`
        };

        const response = await this.withTimeout(
          firewall.analyzePrompt(request),
          timeoutMs
        );

        const success = response.decision === 'ALLOW';

        return {
          attackId: attack.id,
          success,
          firewallResponse: response,
          timestamp: new Date(),
          metrics: {
            processingTime: response.processingTime,
            confidence: response.attackCategory.confidence,
            bypassMethod: success ? attack.category.type : undefined
          }
        };

      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        if (attempt < retryAttempts) {
          // Wait before retry with exponential backoff
          await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
        }
      }
    }

    throw lastError || new Error('Unknown error during attack processing');
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error(`Operation timed out after ${timeoutMs}ms`)), timeoutMs)
      )
    ]);
  }

  private calculateBaselineMetrics(attackResults: AttackResult[]): BaselineMetrics {
    if (attackResults.length === 0) {
      return {
        totalAttacks: 0,
        blockedAttacks: 0,
        flaggedAttacks: 0,
        allowedAttacks: 0,
        blockRate: 0,
        falsePositiveRate: 0, // Cannot calculate without legitimate requests
        bypassRate: 0,
        averageProcessingTime: 0,
        averageRiskScore: 0
      };
    }

    const blockedAttacks = attackResults.filter(r => r.firewallResponse.decision === 'BLOCK').length;
    const flaggedAttacks = attackResults.filter(r => r.firewallResponse.decision === 'FLAG').length;
    const allowedAttacks = attackResults.filter(r => r.firewallResponse.decision === 'ALLOW').length;

    const totalProcessingTime = attackResults.reduce((sum, r) => sum + r.firewallResponse.processingTime, 0);
    const totalRiskScore = attackResults.reduce((sum, r) => sum + r.firewallResponse.riskScore, 0);

    return {
      totalAttacks: attackResults.length,
      blockedAttacks,
      flaggedAttacks,
      allowedAttacks,
      blockRate: (blockedAttacks / attackResults.length) * 100,
      falsePositiveRate: 0, // Would need legitimate requests to calculate this
      bypassRate: (allowedAttacks / attackResults.length) * 100,
      averageProcessingTime: totalProcessingTime / attackResults.length,
      averageRiskScore: totalRiskScore / attackResults.length
    };
  }

  private generateBenchmarkSummary(baselineResults: BaselineResult[]): BenchmarkSummary {
    const totalAttacks = baselineResults.reduce((sum, r) => sum + r.metrics.totalAttacks, 0);
    const totalTime = baselineResults.reduce((sum, r) => sum + r.executionTimeMs, 0);

    // Find top performing baseline (highest block rate)
    const topPerforming = baselineResults.reduce((best, current) => 
      current.metrics.blockRate > best.metrics.blockRate ? current : best
    );

    // Generate pairwise comparisons
    const comparisons: BaselineComparison[] = [];
    for (let i = 0; i < baselineResults.length; i++) {
      for (let j = i + 1; j < baselineResults.length; j++) {
        const baseline1 = baselineResults[i];
        const baseline2 = baselineResults[j];
        
        comparisons.push({
          baseline1: baseline1.baselineType,
          baseline2: baseline2.baselineType,
          blockRateDifference: baseline1.metrics.blockRate - baseline2.metrics.blockRate,
          bypassRateDifference: baseline1.metrics.bypassRate - baseline2.metrics.bypassRate,
          processingTimeDifference: baseline1.metrics.averageProcessingTime - baseline2.metrics.averageProcessingTime,
          statisticalSignificance: Math.abs(baseline1.metrics.blockRate - baseline2.metrics.blockRate) > 5 // Simple threshold
        });
      }
    }

    // Generate significant findings
    const findings: string[] = [];
    
    if (baselineResults.length > 1) {
      const blockRates = baselineResults.map(r => r.metrics.blockRate);
      const maxBlockRate = Math.max(...blockRates);
      const minBlockRate = Math.min(...blockRates);
      
      if (maxBlockRate - minBlockRate > 20) {
        findings.push(`Significant variation in block rates: ${minBlockRate.toFixed(1)}% to ${maxBlockRate.toFixed(1)}%`);
      }
      
      const processingTimes = baselineResults.map(r => r.metrics.averageProcessingTime);
      const maxTime = Math.max(...processingTimes);
      const minTime = Math.min(...processingTimes);
      
      if (maxTime > minTime * 2) {
        findings.push(`Processing time varies significantly: ${minTime.toFixed(1)}ms to ${maxTime.toFixed(1)}ms`);
      }
    }

    return {
      totalAttacksProcessed: totalAttacks,
      totalExecutionTimeMs: totalTime,
      baselineComparison: comparisons,
      topPerformingBaseline: topPerforming.baselineType,
      significantFindings: findings
    };
  }

  private generateReproducibilityHash(config: BenchmarkConfiguration, dataset: AttackDataset): string {
    // Create a hash of all factors that should remain constant for reproducible results
    const hashInput = {
      configId: config.id,
      datasetId: dataset.id,
      datasetVersion: dataset.version,
      attackCount: dataset.attacks.length,
      attackHashes: dataset.attacks.map(a => `${a.id}-${a.prompt.length}`).sort(),
      testConditions: config.testConditions,
      baselineTypes: config.baselineTypes.filter(b => b.enabled).map(b => b.name).sort()
    };

    // Simple hash function (in production, use a proper cryptographic hash)
    return Buffer.from(JSON.stringify(hashInput)).toString('base64');
  }

  private seededRandom(seed: number): () => number {
    let state = seed;
    return function() {
      state = (state * 9301 + 49297) % 233280;
      return state / 233280;
    };
  }

  async getResult(resultId: string): Promise<BenchmarkResult | null> {
    return await this.database.getBenchmarkResult(resultId);
  }

  async listConfigurations(): Promise<BenchmarkConfiguration[]> {
    return await this.database.listBenchmarkConfigurations();
  }

  async listResults(configId?: string): Promise<BenchmarkResult[]> {
    return await this.database.listBenchmarkResults(configId);
  }

  async validateReproducibility(result1Id: string, result2Id: string): Promise<boolean> {
    const result1 = await this.getResult(result1Id);
    const result2 = await this.getResult(result2Id);

    if (!result1 || !result2) {
      throw new Error('One or both benchmark results not found');
    }

    // Check if reproducibility hashes match
    if (result1.reproducibilityHash !== result2.reproducibilityHash) {
      return false;
    }

    // Check if results are substantially similar
    const tolerance = 0.01; // 1% tolerance for floating point comparisons

    for (const baseline1 of result1.baselineResults) {
      const baseline2 = result2.baselineResults.find(b => b.baselineType === baseline1.baselineType);
      if (!baseline2) {
        return false;
      }

      // Compare key metrics
      if (Math.abs(baseline1.metrics.blockRate - baseline2.metrics.blockRate) > tolerance ||
          Math.abs(baseline1.metrics.bypassRate - baseline2.metrics.bypassRate) > tolerance) {
        return false;
      }
    }

    return true;
  }

  /**
   * Generate comprehensive report for benchmark results
   */
  async generateReport(resultId: string): Promise<any> {
    const result = await this.getResult(resultId);
    if (!result) {
      throw new Error(`Benchmark result ${resultId} not found`);
    }

    return this.reportGenerator.generateReport(result);
  }

  /**
   * Export benchmark results in specified format
   */
  async exportResults(resultId: string, format: 'JSON' | 'CSV' | 'HTML' | 'PDF'): Promise<any> {
    const result = await this.getResult(resultId);
    if (!result) {
      throw new Error(`Benchmark result ${resultId} not found`);
    }

    return this.exporter.exportBenchmarkResults(result, format);
  }

  /**
   * Export comparison report for multiple benchmark results
   */
  async exportComparisonReport(resultIds: string[], format: 'JSON' | 'CSV' | 'HTML'): Promise<any> {
    const results: BenchmarkResult[] = [];
    
    for (const resultId of resultIds) {
      const result = await this.getResult(resultId);
      if (result) {
        results.push(result);
      }
    }

    if (results.length === 0) {
      throw new Error('No valid benchmark results found for comparison');
    }

    return this.exporter.exportComparisonReport(results, format);
  }

  /**
   * Calculate detailed evaluation metrics for a specific baseline result
   */
  calculateDetailedMetrics(baselineResult: BaselineResult): any {
    return this.metricsCalculator.calculateMetrics(baselineResult.attackResults);
  }

  /**
   * Compare two baseline results and provide detailed analysis
   */
  compareBaselineResults(baseline1: BaselineResult, baseline2: BaselineResult): any {
    const metrics1 = this.metricsCalculator.calculateMetrics(baseline1.attackResults);
    const metrics2 = this.metricsCalculator.calculateMetrics(baseline2.attackResults);
    
    return this.metricsCalculator.compareBaselines(
      metrics1, 
      metrics2, 
      baseline1.baselineType, 
      baseline2.baselineType
    );
  }
}

// Simple semaphore implementation for controlling concurrency
class Semaphore {
  private permits: number;
  private waitQueue: (() => void)[] = [];

  constructor(permits: number) {
    this.permits = permits;
  }

  async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return;
    }

    return new Promise<void>((resolve) => {
      this.waitQueue.push(resolve);
    });
  }

  release(): void {
    if (this.waitQueue.length > 0) {
      const resolve = this.waitQueue.shift()!;
      resolve();
    } else {
      this.permits++;
    }
  }
}