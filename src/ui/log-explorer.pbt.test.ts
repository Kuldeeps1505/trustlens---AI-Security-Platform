/**
 * Property-based tests for Security Log Explorer filtering accuracy
 * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
 * **Validates: Requirements 8.2**
 */

import { describe, it, expect, beforeEach } from 'vitest';
import fc from 'fast-check';
import { SecurityLogExplorer, LogFilter, LogSearchQuery } from './log-explorer';
import { AuditLogEntry, FirewallResponse, AttackCategory } from '../types/core';

describe('Security Log Explorer Filtering Properties', () => {
  let logExplorer: SecurityLogExplorer;

  beforeEach(() => {
    logExplorer = new SecurityLogExplorer();
  });

  // Generator for audit log entries
  const auditLogGenerator = fc.record({
    id: fc.string({ minLength: 1, maxLength: 20 }),
    timestamp: fc.date({ min: new Date('2024-01-01'), max: new Date('2024-12-31') }),
    eventType: fc.constantFrom('FIREWALL_DECISION', 'ATTACK_GENERATED', 'DEFENSE_UPDATED', 'SCORE_CALCULATED'),
    userId: fc.option(fc.string({ minLength: 1, maxLength: 15 })),
    sessionId: fc.option(fc.string({ minLength: 1, maxLength: 15 })),
    riskScore: fc.integer({ min: 0, max: 100 }),
    decision: fc.constantFrom('ALLOW', 'BLOCK', 'FLAG'),
    attackType: fc.constantFrom('PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'),
    prompt: fc.option(fc.string({ minLength: 1, maxLength: 100 })),
    explanation: fc.option(fc.string({ minLength: 1, maxLength: 50 })),
    processingTime: fc.integer({ min: 1, max: 1000 })
  }).map(data => {
    const attackCategory: AttackCategory = {
      type: data.attackType,
      confidence: 0.8,
      indicators: ['test_indicator']
    };

    const firewallResponse: FirewallResponse = {
      decision: data.decision,
      riskScore: data.riskScore,
      attackCategory,
      explanation: data.explanation || 'Test explanation',
      processingTime: data.processingTime,
      ruleVersion: '1.0.0'
    };

    const auditLog: AuditLogEntry = {
      id: data.id,
      timestamp: data.timestamp,
      eventType: data.eventType,
      userId: data.userId,
      sessionId: data.sessionId,
      data: {
        prompt: data.prompt,
        decision: data.eventType === 'FIREWALL_DECISION' ? firewallResponse : undefined
      },
      metadata: {
        processingTime: data.processingTime
      }
    };

    return auditLog;
  });

  it('Property 26: Log filtering accuracy - time range filters work correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any time range filter, all returned logs should fall within the specified time bounds
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 5, maxLength: 50 }),
      fc.record({
        startTime: fc.date({ min: new Date('2024-01-01'), max: new Date('2024-06-30') }),
        endTime: fc.date({ min: new Date('2024-07-01'), max: new Date('2024-12-31') })
      }),
      
      async (logs, timeFilter) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          startTime: timeFilter.startTime,
          endTime: timeFilter.endTime
        };
        
        const result = await logExplorer.filterLogs(filter);
        
        // All returned logs should be within the time range
        result.logs.forEach(log => {
          expect(log.timestamp.getTime()).toBeGreaterThanOrEqual(timeFilter.startTime.getTime());
          expect(log.timestamp.getTime()).toBeLessThanOrEqual(timeFilter.endTime.getTime());
        });
        
        // Verify count accuracy
        const manualCount = logs.filter(log => 
          log.timestamp >= timeFilter.startTime && log.timestamp <= timeFilter.endTime
        ).length;
        
        expect(result.filteredCount).toBe(manualCount);
      }
    ), { numRuns: 100 });
  });

  it('Property 26: Log filtering accuracy - event type filters work correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any event type filter, all returned logs should match the specified event types
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 10, maxLength: 100 }),
      fc.array(fc.constantFrom('FIREWALL_DECISION', 'ATTACK_GENERATED', 'DEFENSE_UPDATED', 'SCORE_CALCULATED'), 
               { minLength: 1, maxLength: 4 }),
      
      async (logs, eventTypes) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          eventType: eventTypes
        };
        
        const result = await logExplorer.filterLogs(filter);
        
        // All returned logs should have matching event types
        result.logs.forEach(log => {
          expect(eventTypes).toContain(log.eventType);
        });
        
        // Verify count accuracy
        const manualCount = logs.filter(log => eventTypes.includes(log.eventType)).length;
        expect(result.filteredCount).toBe(manualCount);
      }
    ), { numRuns: 100 });
  });

  it('Property 26: Log filtering accuracy - risk score range filters work correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any risk score range filter, all returned logs should have risk scores within the specified range
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 10, maxLength: 100 }),
      fc.record({
        riskScoreMin: fc.integer({ min: 0, max: 50 }),
        riskScoreMax: fc.integer({ min: 51, max: 100 })
      }),
      
      async (logs, riskRange) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          riskScoreMin: riskRange.riskScoreMin,
          riskScoreMax: riskRange.riskScoreMax
        };
        
        const result = await logExplorer.filterLogs(filter);
        
        // All returned logs should have risk scores within range
        result.logs.forEach(log => {
          if (log.data.decision) {
            expect(log.data.decision.riskScore).toBeGreaterThanOrEqual(riskRange.riskScoreMin);
            expect(log.data.decision.riskScore).toBeLessThanOrEqual(riskRange.riskScoreMax);
          }
        });
        
        // Verify count accuracy
        const manualCount = logs.filter(log => 
          log.data.decision && 
          log.data.decision.riskScore >= riskRange.riskScoreMin &&
          log.data.decision.riskScore <= riskRange.riskScoreMax
        ).length;
        
        expect(result.filteredCount).toBe(manualCount);
      }
    ), { numRuns: 100 });
  });

  it('Property 26: Log filtering accuracy - user and session filters work correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any user ID or session ID filter, all returned logs should match the specified identifiers
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 10, maxLength: 100 }),
      fc.record({
        userId: fc.option(fc.string({ minLength: 1, maxLength: 15 })),
        sessionId: fc.option(fc.string({ minLength: 1, maxLength: 15 }))
      }),
      
      async (logs, identifiers) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          userId: identifiers.userId || undefined,
          sessionId: identifiers.sessionId || undefined
        };
        
        const result = await logExplorer.filterLogs(filter);
        
        // All returned logs should match the specified identifiers
        result.logs.forEach(log => {
          if (filter.userId) {
            expect(log.userId).toBe(filter.userId);
          }
          if (filter.sessionId) {
            expect(log.sessionId).toBe(filter.sessionId);
          }
        });
        
        // Verify count accuracy
        const manualCount = logs.filter(log => {
          let matches = true;
          if (filter.userId && log.userId !== filter.userId) matches = false;
          if (filter.sessionId && log.sessionId !== filter.sessionId) matches = false;
          return matches;
        }).length;
        
        expect(result.filteredCount).toBe(manualCount);
      }
    ), { numRuns: 100 });
  });

  it('Property 26: Log filtering accuracy - decision type filters work correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any decision type filter, all returned logs should match the specified decision types
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 10, maxLength: 100 }),
      fc.array(fc.constantFrom('ALLOW', 'BLOCK', 'FLAG'), { minLength: 1, maxLength: 3 }),
      
      async (logs, decisions) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          decision: decisions
        };
        
        const result = await logExplorer.filterLogs(filter);
        
        // All returned logs should have matching decision types
        result.logs.forEach(log => {
          if (log.data.decision) {
            expect(decisions).toContain(log.data.decision.decision);
          }
        });
        
        // Verify count accuracy
        const manualCount = logs.filter(log => 
          log.data.decision && decisions.includes(log.data.decision.decision)
        ).length;
        
        expect(result.filteredCount).toBe(manualCount);
      }
    ), { numRuns: 100 });
  });

  it('Property 26: Log filtering accuracy - search functionality works correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any search query, all returned logs should contain the search term in the specified fields
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 5, maxLength: 50 }),
      fc.record({
        searchTerm: fc.string({ minLength: 1, maxLength: 10 }),
        searchFields: fc.array(fc.constantFrom('prompt', 'explanation', 'userId', 'sessionId'), 
                              { minLength: 1, maxLength: 4 }),
        caseSensitive: fc.boolean()
      }),
      
      async (logs, searchConfig) => {
        await logExplorer.loadLogs(logs);
        
        const searchQuery: LogSearchQuery = {
          searchTerm: searchConfig.searchTerm,
          searchFields: searchConfig.searchFields,
          caseSensitive: searchConfig.caseSensitive,
          useRegex: false
        };
        
        const result = await logExplorer.searchLogs(searchQuery);
        
        // All returned logs should contain the search term in at least one specified field
        result.logs.forEach(log => {
          const foundInField = searchConfig.searchFields.some(field => {
            let fieldValue = '';
            
            switch (field) {
              case 'prompt':
                fieldValue = log.data.prompt || '';
                break;
              case 'explanation':
                fieldValue = log.data.decision?.explanation || '';
                break;
              case 'userId':
                fieldValue = log.userId || '';
                break;
              case 'sessionId':
                fieldValue = log.sessionId || '';
                break;
            }
            
            if (!searchConfig.caseSensitive) {
              fieldValue = fieldValue.toLowerCase();
            }
            
            const searchTerm = searchConfig.caseSensitive 
              ? searchConfig.searchTerm 
              : searchConfig.searchTerm.toLowerCase();
            
            return fieldValue.includes(searchTerm);
          });
          
          expect(foundInField).toBe(true);
        });
      }
    ), { numRuns: 50 });
  });

  it('Property 26: Log filtering accuracy - combined filters work correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any combination of filters, all returned logs should satisfy ALL filter conditions
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 20, maxLength: 100 }),
      fc.record({
        eventType: fc.option(fc.array(fc.constantFrom('FIREWALL_DECISION', 'ATTACK_GENERATED'), 
                                     { minLength: 1, maxLength: 2 })),
        decision: fc.option(fc.array(fc.constantFrom('ALLOW', 'BLOCK'), { minLength: 1, maxLength: 2 })),
        riskScoreMin: fc.option(fc.integer({ min: 0, max: 30 })),
        riskScoreMax: fc.option(fc.integer({ min: 70, max: 100 }))
      }),
      
      async (logs, filterConfig) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          eventType: filterConfig.eventType || undefined,
          decision: filterConfig.decision || undefined,
          riskScoreMin: filterConfig.riskScoreMin || undefined,
          riskScoreMax: filterConfig.riskScoreMax || undefined
        };
        
        const result = await logExplorer.filterLogs(filter);
        
        // All returned logs should satisfy ALL filter conditions
        result.logs.forEach(log => {
          // Check event type filter
          if (filter.eventType) {
            expect(filter.eventType).toContain(log.eventType);
          }
          
          // Check decision filter
          if (filter.decision && log.data.decision) {
            expect(filter.decision).toContain(log.data.decision.decision);
          }
          
          // Check risk score range
          if (log.data.decision) {
            if (filter.riskScoreMin !== undefined) {
              expect(log.data.decision.riskScore).toBeGreaterThanOrEqual(filter.riskScoreMin);
            }
            if (filter.riskScoreMax !== undefined) {
              expect(log.data.decision.riskScore).toBeLessThanOrEqual(filter.riskScoreMax);
            }
          }
        });
        
        // Verify count accuracy with manual filtering
        const manualCount = logs.filter(log => {
          // Event type check
          if (filter.eventType && !filter.eventType.includes(log.eventType)) return false;
          
          // Decision check - only apply to logs that have decisions
          if (filter.decision) {
            if (!log.data.decision || !filter.decision.includes(log.data.decision.decision)) return false;
          }
          
          // Risk score range check - only apply to logs that have decisions
          if ((filter.riskScoreMin !== undefined || filter.riskScoreMax !== undefined) && log.data.decision) {
            if (filter.riskScoreMin !== undefined && log.data.decision.riskScore < filter.riskScoreMin) return false;
            if (filter.riskScoreMax !== undefined && log.data.decision.riskScore > filter.riskScoreMax) return false;
          } else if ((filter.riskScoreMin !== undefined || filter.riskScoreMax !== undefined) && !log.data.decision) {
            // If we're filtering by risk score but the log has no decision, exclude it
            return false;
          }
          
          return true;
        }).length;
        
        expect(result.filteredCount).toBe(manualCount);
      }
    ), { numRuns: 50 });
  });

  it('Property 26: Log filtering accuracy - pagination preserves filter results', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 26: Log filtering accuracy**
     * **Validates: Requirements 8.2**
     * 
     * For any filter with pagination, the total filtered count should remain consistent
     * across different page sizes and page numbers
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(auditLogGenerator, { minLength: 50, maxLength: 200 }),
      fc.record({
        eventType: fc.array(fc.constantFrom('FIREWALL_DECISION', 'ATTACK_GENERATED'), 
                           { minLength: 1, maxLength: 2 }),
        pageSize: fc.integer({ min: 5, max: 20 }),
        page: fc.integer({ min: 1, max: 5 })
      }),
      
      async (logs, config) => {
        await logExplorer.loadLogs(logs);
        
        const filter: LogFilter = {
          eventType: config.eventType
        };
        
        // Get results with different page configurations
        const result1 = await logExplorer.filterLogs(filter, config.page, config.pageSize);
        const result2 = await logExplorer.filterLogs(filter, 1, config.pageSize * 2);
        
        // Filtered count should be consistent regardless of pagination
        expect(result1.filteredCount).toBe(result2.filteredCount);
        
        // Total count should always be the same
        expect(result1.totalCount).toBe(result2.totalCount);
        expect(result1.totalCount).toBe(logs.length);
        
        // Returned logs should not exceed page size
        expect(result1.logs.length).toBeLessThanOrEqual(config.pageSize);
        
        // All returned logs should match the filter
        result1.logs.forEach(log => {
          expect(config.eventType).toContain(log.eventType);
        });
      }
    ), { numRuns: 50 });
  });
});