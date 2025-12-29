/**
 * Minimal Benchmark Service to isolate the issue
 */

import { v4 as uuidv4 } from 'uuid';
import { AttackDataset, Attack, FirewallRequest, FirewallResponse, AttackResult } from '../types/core';
import { FirewallService } from '../api/firewall';
import { AttackDatasetManager } from '../data/attack-dataset';
import { SQLiteDatabase } from '../data/database';

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

export class BenchmarkService {
  private database: SQLiteDatabase;
  private datasetManager: AttackDatasetManager;
  private firewallService: FirewallService;
  private simpleRuleFirewall: SimpleRuleFirewall;
  private noDefenseFirewall: NoDefenseFirewall;

  constructor(database: SQLiteDatabase, datasetManager: AttackDatasetManager, firewallService: FirewallService) {
    this.database = database;
    this.datasetManager = datasetManager;
    this.firewallService = firewallService;
    this.simpleRuleFirewall = new SimpleRuleFirewall();
    this.noDefenseFirewall = new NoDefenseFirewall();
  }

  async createConfiguration(config: Omit<BenchmarkConfiguration, 'id' | 'createdAt'>): Promise<BenchmarkConfiguration> {
    const configuration: BenchmarkConfiguration = {
      id: uuidv4(),
      createdAt: new Date(),
      ...config
    };

    return configuration;
  }
}