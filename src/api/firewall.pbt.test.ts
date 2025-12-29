/**
 * Property-based tests for AI Firewall API Gateway
 * Tests universal properties that should hold across all valid executions
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fc from 'fast-check';
import { FirewallService } from './firewall';
import { firewallRequestArb } from '../test-utils/generators';
import { SQLiteDatabase } from '../data/database';

describe('AI Firewall Property-Based Tests', () => {
  const database = new SQLiteDatabase();
  const firewallService = new FirewallService(database);

  beforeAll(async () => {
    await firewallService.initialize();
  });

  afterAll(async () => {
    await database.disconnect();
  });

  it('Property 1: Firewall response completeness - **Feature: trustlens-ai-security-platform, Property 1: Firewall response completeness** - **Validates: Requirements 1.1, 1.2, 1.3**', async () => {
    await fc.assert(
      fc.asyncProperty(firewallRequestArb, async (request) => {
        const response = await firewallService.analyzePrompt(request);

        // Response should always contain a valid decision
        expect(['ALLOW', 'BLOCK', 'FLAG']).toContain(response.decision);

        // Risk score should be between 0-100
        expect(response.riskScore).toBeGreaterThanOrEqual(0);
        expect(response.riskScore).toBeLessThanOrEqual(100);

        // Attack category should be present and valid
        expect(response.attackCategory).toBeDefined();
        expect(['PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'])
          .toContain(response.attackCategory.type);
        expect(response.attackCategory.confidence).toBeGreaterThanOrEqual(0);
        expect(response.attackCategory.confidence).toBeLessThanOrEqual(1);
        expect(Array.isArray(response.attackCategory.indicators)).toBe(true);

        // Human-readable explanation should be present
        expect(response.explanation).toBeDefined();
        expect(typeof response.explanation).toBe('string');
        expect(response.explanation.length).toBeGreaterThan(0);

        // Processing time should be a positive number
        expect(response.processingTime).toBeGreaterThanOrEqual(0);
        expect(typeof response.processingTime).toBe('number');

        // Rule version should be present
        expect(response.ruleVersion).toBeDefined();
        expect(typeof response.ruleVersion).toBe('string');
        expect(response.ruleVersion.length).toBeGreaterThan(0);
      }),
      { numRuns: 100 }
    );
  });

  it('Property 3: Input-output processing consistency - **Feature: trustlens-ai-security-platform, Property 3: Input-output processing consistency** - **Validates: Requirements 1.5**', async () => {
    await fc.assert(
      fc.asyncProperty(fc.string({ minLength: 1, maxLength: 1000 }), async (content) => {
        // Analyze the same content as both input prompt and output
        const promptResponse = await firewallService.analyzePrompt({ prompt: content });
        const outputResponse = await firewallService.analyzeOutput(content);

        // Both should use the same detection and logging mechanisms
        // The responses should be structurally identical (same fields and types)
        expect(typeof promptResponse.decision).toBe(typeof outputResponse.decision);
        expect(typeof promptResponse.riskScore).toBe(typeof outputResponse.riskScore);
        expect(typeof promptResponse.attackCategory).toBe(typeof outputResponse.attackCategory);
        expect(typeof promptResponse.explanation).toBe(typeof outputResponse.explanation);
        expect(typeof promptResponse.processingTime).toBe(typeof outputResponse.processingTime);
        expect(typeof promptResponse.ruleVersion).toBe(typeof outputResponse.ruleVersion);

        // Risk scores should be identical for the same content
        expect(promptResponse.riskScore).toBe(outputResponse.riskScore);
        
        // Decisions should be identical for the same content
        expect(promptResponse.decision).toBe(outputResponse.decision);
        
        // Attack categories should be identical for the same content
        expect(promptResponse.attackCategory.type).toBe(outputResponse.attackCategory.type);
        expect(promptResponse.attackCategory.confidence).toBe(outputResponse.attackCategory.confidence);
        expect(promptResponse.attackCategory.indicators).toEqual(outputResponse.attackCategory.indicators);
      }),
      { numRuns: 100 }
    );
  });

  it('Property 2: Comprehensive audit logging - **Feature: trustlens-ai-security-platform, Property 2: Comprehensive audit logging** - **Validates: Requirements 1.4, 8.1**', async () => {
    await fc.assert(
      fc.asyncProperty(firewallRequestArb, async (request) => {
        // Make a firewall decision
        const response = await firewallService.analyzePrompt(request);
        
        // Wait for async logging to complete
        await new Promise(resolve => setTimeout(resolve, 50));
        
        // Check that audit log was created
        const logs = await firewallService['database'].getLogEntries({
          eventType: 'FIREWALL_DECISION',
          userId: request.userId,
          sessionId: request.sessionId
        });
        
        // Should have at least one log entry for this request
        expect(logs.length).toBeGreaterThan(0);
        
        // Find the log entry for this specific request
        const matchingLog = logs.find(log => 
          log.data.prompt === request.prompt &&
          log.userId === request.userId &&
          log.sessionId === request.sessionId
        );
        
        expect(matchingLog).toBeDefined();
        
        if (matchingLog) {
          // Verify audit log contains all required fields
          expect(matchingLog.id).toBeDefined();
          expect(typeof matchingLog.id).toBe('string');
          expect(matchingLog.id.length).toBeGreaterThan(0);
          
          expect(matchingLog.timestamp).toBeInstanceOf(Date);
          expect(matchingLog.eventType).toBe('FIREWALL_DECISION');
          
          // Verify data contains prompt, classification, decision, reason, and score impact
          expect(matchingLog.data.prompt).toBe(request.prompt);
          expect(matchingLog.data.decision).toEqual(response);
          
          // Verify metadata contains processing time with precise timestamp
          expect(matchingLog.metadata.processingTime).toBe(response.processingTime);
          expect(typeof matchingLog.metadata.processingTime).toBe('number');
          expect(matchingLog.metadata.processingTime).toBeGreaterThanOrEqual(0);
        }
      }),
      { numRuns: 20 } // Reduced runs for performance since this involves database operations
    );
  });
});