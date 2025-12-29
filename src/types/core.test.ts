/**
 * Unit tests for core TypeScript interfaces
 * Validates type definitions and basic functionality
 */

import { describe, it, expect } from 'vitest';
import { 
  FirewallRequest, 
  FirewallResponse, 
  Attack, 
  AttackResult, 
  TrustScore,
  TrustScoreComponents,
  AttackCategory
} from './core';

describe('Core Types', () => {
  describe('FirewallRequest', () => {
    it('should accept valid firewall request', () => {
      const request: FirewallRequest = {
        prompt: 'Test prompt',
        context: 'Test context',
        userId: 'user123',
        sessionId: 'session456'
      };
      
      expect(request.prompt).toBe('Test prompt');
      expect(request.context).toBe('Test context');
      expect(request.userId).toBe('user123');
      expect(request.sessionId).toBe('session456');
    });

    it('should accept minimal firewall request', () => {
      const request: FirewallRequest = {
        prompt: 'Test prompt'
      };
      
      expect(request.prompt).toBe('Test prompt');
      expect(request.context).toBeUndefined();
      expect(request.userId).toBeUndefined();
      expect(request.sessionId).toBeUndefined();
    });
  });

  describe('FirewallResponse', () => {
    it('should accept valid firewall response', () => {
      const response: FirewallResponse = {
        decision: 'BLOCK',
        riskScore: 85,
        attackCategory: {
          type: 'PROMPT_INJECTION',
          confidence: 0.9,
          indicators: ['suspicious pattern']
        },
        explanation: 'Detected prompt injection attempt',
        processingTime: 50,
        ruleVersion: '1.0.0'
      };
      
      expect(response.decision).toBe('BLOCK');
      expect(response.riskScore).toBe(85);
      expect(response.attackCategory.type).toBe('PROMPT_INJECTION');
      expect(response.explanation).toBe('Detected prompt injection attempt');
    });
  });

  describe('TrustScore', () => {
    it('should accept valid trust score', () => {
      const components: TrustScoreComponents = {
        blockRate: 85,
        falsePositiveRate: 5,
        bypassRate: 10,
        regressionPenalty: 0,
        explainabilityScore: 80
      };

      const trustScore: TrustScore = {
        overall: 75,
        components,
        trend: 'STABLE',
        lastUpdated: new Date(),
        changeReason: 'Test score calculation'
      };
      
      expect(trustScore.overall).toBe(75);
      expect(trustScore.components.blockRate).toBe(85);
      expect(trustScore.trend).toBe('STABLE');
    });
  });

  describe('Attack', () => {
    it('should accept valid attack object', () => {
      const attack: Attack = {
        id: 'attack-123',
        prompt: 'Malicious prompt',
        category: {
          type: 'JAILBREAK',
          confidence: 0.8,
          indicators: ['role manipulation']
        },
        generation: 1,
        metadata: {
          createdAt: new Date(),
          source: 'AI_GENERATED',
          severity: 'HIGH'
        }
      };
      
      expect(attack.id).toBe('attack-123');
      expect(attack.category.type).toBe('JAILBREAK');
      expect(attack.metadata.source).toBe('AI_GENERATED');
    });

    it('should accept attack with parent lineage', () => {
      const attack: Attack = {
        id: 'attack-456',
        prompt: 'Evolved attack',
        category: {
          type: 'INSTRUCTION_OVERRIDE',
          confidence: 0.9,
          indicators: ['instruction bypass']
        },
        parentId: 'attack-123',
        generation: 2,
        metadata: {
          createdAt: new Date(),
          source: 'AI_GENERATED',
          severity: 'CRITICAL'
        }
      };
      
      expect(attack.parentId).toBe('attack-123');
      expect(attack.generation).toBe(2);
    });
  });
});