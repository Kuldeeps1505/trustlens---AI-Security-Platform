/**
 * Property-Based Tests for Security Log Explorer Functionality
 * **Feature: trustlens-ai-security-platform, Property 29: Security log exploration functionality**
 * **Validates: Requirements 9.5**
 */

import { describe, it, expect, beforeEach } from 'vitest';
import fc from 'fast-check';
import { SecurityLogExplorer, LogFilter, LogSearchQuery, LogExportOptions } from './log-explorer';
import { AuditLogEntry } from '../types/core';
import { v4 as uuidv4 } from 'uuid';

describe('Security Log Explorer Functionality Property Tests', () => {
  let logExplorer: SecurityLogExplorer;

  beforeEach(() => {
    logExplorer = new SecurityLogExplorer();
  });

  // Generator for audit log entries
  const auditLogEntryArb = fc.record({
    id: fc.string({ minLength: 1, maxLength: 50 }).map(() => uuidv4()),
    timestamp: fc.date({ min: new Date('2020-01-01'), max: new Date('2030-01-01') }),
    eventType: fc.constantFrom('FIREWALL_DECISION', 'ATTACK_GENERATED', 'DEFENSE_UPDATED', 'SCORE_CALCULATED'),
    userId: fc.option(fc.string({ minLength: 1, maxLength: 50 }), { nil: undefined }),
    sessionId: fc.option(fc.string({ minLength: 1, maxLength: 50 }), { nil: undefined }),
    data: fc.record({
      prompt: fc.option(fc.string({ maxLength: 1000 }), { nil: undefined }),
      decision: fc.option(fc.record({
        decision: fc.constantFrom('ALLOW', 'BLOCK', 'FLAG'),
        riskScore: fc.integer({ min: 0, max: 100 }),
        attackCategory: fc.record({
          type: fc.constantFrom('PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'),
          confidence: fc.float({ min: 0, max: 1 }),
          indicators: fc.array(fc.string({ maxLength: 100 }), { maxLength: 5 })
        }),
        explanation: fc.string({ maxLength: 500 }),
        processingTime: fc.integer({ min: 1, max: 5000 }),
        ruleVersion: fc.string({ minLength: 1, maxLength: 10 })
      }), { nil: undefined }),
      trustScoreChange: fc.option(fc.float({ min: -100, max: 100 }), { nil: undefined }),
      defenseVersion: fc.option(fc.string({ minLength: 1, maxLength: 20 }), { nil: undefined })
    }),
    metadata: fc.record({
      ipAddress: fc.option(fc.string({ maxLength: 50 }), { nil: undefined }),
      userAgent: fc.option(fc.string({ maxLength: 200 }), { nil: undefined }),
      processingTime: fc.integer({ min: 1, max: 5000 })
    })
  }) as fc.Arbitrary<AuditLogEntry>;

  // Generator for log filters
  const logFilterArb = fc.record({
    startTime: fc.option(fc.date({ min: new Date('2020-01-01'), max: new Date('2025-01-01') }), { nil: undefined }),
    endTime: fc.option(fc.date({ min: new Date('2025-01-01'), max: new Date('2030-01-01') }), { nil: undefined }),
    severity: fc.option(fc.array(fc.constantFrom('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), { minLength: 1, maxLength: 4 }), { nil: undefined }),
    attackType: fc.option(fc.array(fc.constantFrom('PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'), { minLength: 1, maxLength: 4 }), { nil: undefined }),
    eventType: fc.option(fc.array(fc.constantFrom('FIREWALL_DECISION', 'ATTACK_GENERATED', 'DEFENSE_UPDATED', 'SCORE_CALCULATED'), { minLength: 1, maxLength: 4 }), { nil: undefined }),
    userId: fc.option(fc.string({ minLength: 1, maxLength: 50 }), { nil: undefined }),
    sessionId: fc.option(fc.string({ minLength: 1, maxLength: 50 }), { nil: undefined }),
    decision: fc.option(fc.array(fc.constantFrom('ALLOW', 'BLOCK', 'FLAG'), { minLength: 1, maxLength: 3 }), { nil: undefined }),
    riskScoreMin: fc.option(fc.integer({ min: 0, max: 50 }), { nil: undefined }),
    riskScoreMax: fc.option(fc.integer({ min: 50, max: 100 }), { nil: undefined })
  }) as fc.Arbitrary<LogFilter>;

  // Generator for search queries
  const searchQueryArb = fc.record({
    searchTerm: fc.string({ minLength: 1, maxLength: 100 }).filter(s => s.trim().length > 0), // Exclude empty/whitespace-only strings
    searchFields: fc.array(fc.constantFrom('prompt', 'explanation', 'userId', 'sessionId'), { minLength: 1, maxLength: 4 }),
    caseSensitive: fc.boolean(),
    useRegex: fc.boolean()
  }) as fc.Arbitrary<LogSearchQuery>;

  /**
   * Property 29: Security log exploration functionality
   * For any set of audit logs and any valid filter, the filtering operation should
   * return only logs that match the filter criteria
   */
  it('should filter logs correctly according to filter criteria', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(auditLogEntryArb, { minLength: 5, maxLength: 50 }),
        logFilterArb,
        async (logs, filter) => {
          // Load logs into explorer
          await logExplorer.loadLogs(logs);

          // Apply filter
          const result = await logExplorer.filterLogs(filter, 1, 1000);

          // Verify all returned logs match the filter criteria
          for (const log of result.logs) {
            // Check time range
            if (filter.startTime) {
              expect(log.timestamp.getTime()).toBeGreaterThanOrEqual(filter.startTime.getTime());
            }
            if (filter.endTime) {
              expect(log.timestamp.getTime()).toBeLessThanOrEqual(filter.endTime.getTime());
            }

            // Check event type
            if (filter.eventType && filter.eventType.length > 0) {
              expect(filter.eventType).toContain(log.eventType);
            }

            // Check user ID
            if (filter.userId) {
              expect(log.userId).toBe(filter.userId);
            }

            // Check session ID
            if (filter.sessionId) {
              expect(log.sessionId).toBe(filter.sessionId);
            }

            // Check decision
            if (filter.decision && filter.decision.length > 0 && log.data.decision) {
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

            // Check attack type
            if (filter.attackType && filter.attackType.length > 0 && log.data.decision) {
              expect(filter.attackType).toContain(log.data.decision.attackCategory.type);
            }
          }

          // Verify result metadata
          expect(result.totalCount).toBe(logs.length);
          expect(result.filteredCount).toBeLessThanOrEqual(logs.length);
          expect(result.logs.length).toBeLessThanOrEqual(result.filteredCount);
          expect(result.executionTime).toBeGreaterThan(0);
        }
      ),
      { numRuns: 30 }
    );
  });

  /**
   * Property: Search functionality returns relevant results
   * For any set of logs and search query, all returned results should contain
   * the search term in at least one of the specified search fields
   */
  it('should return search results that contain the search term in specified fields', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(auditLogEntryArb, { minLength: 10, maxLength: 30 }),
        searchQueryArb,
        async (logs, query) => {
          // Skip regex tests that might be invalid
          if (query.useRegex) {
            try {
              new RegExp(query.searchTerm);
            } catch {
              return; // Skip invalid regex patterns
            }
          }

          // Load logs into explorer
          await logExplorer.loadLogs(logs);

          // Perform search
          const result = await logExplorer.searchLogs(query, undefined, 1, 1000);

          // Verify all returned logs contain the search term in specified fields
          for (const log of result.logs) {
            let foundMatch = false;

            for (const field of query.searchFields) {
              let searchValue = '';
              
              switch (field) {
                case 'prompt':
                  searchValue = log.data.prompt || '';
                  break;
                case 'explanation':
                  searchValue = log.data.decision?.explanation || '';
                  break;
                case 'userId':
                  searchValue = log.userId || '';
                  break;
                case 'sessionId':
                  searchValue = log.sessionId || '';
                  break;
              }

              let searchTerm = query.searchTerm;
              if (!query.caseSensitive) {
                searchValue = searchValue.toLowerCase();
                searchTerm = searchTerm.toLowerCase();
              }

              if (query.useRegex) {
                try {
                  const regex = new RegExp(searchTerm, query.caseSensitive ? 'g' : 'gi');
                  if (regex.test(searchValue)) {
                    foundMatch = true;
                    break;
                  }
                } catch {
                  // Fall back to string search for invalid regex
                  if (searchValue.includes(searchTerm)) {
                    foundMatch = true;
                    break;
                  }
                }
              } else {
                if (searchValue.includes(searchTerm)) {
                  foundMatch = true;
                  break;
                }
              }
            }

            expect(foundMatch).toBe(true);
          }

          // Verify result metadata
          expect(result.totalCount).toBe(logs.length);
          expect(result.filteredCount).toBeLessThanOrEqual(logs.length);
          expect(result.executionTime).toBeGreaterThan(0);
        }
      ),
      { numRuns: 25 }
    );
  });

  /**
   * Property: Export functionality produces valid output
   * For any set of logs and export format, the export should produce
   * valid output in the specified format
   */
  it('should export logs in valid format for all supported export types', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(auditLogEntryArb, { minLength: 1, maxLength: 20 }),
        fc.constantFrom('json', 'csv', 'siem'),
        fc.boolean(), // includeMetadata
        fc.constantFrom('iso', 'unix', 'human'), // dateFormat
        async (logs, format, includeMetadata, dateFormat) => {
          // Load logs into explorer
          await logExplorer.loadLogs(logs);

          const exportOptions: LogExportOptions = {
            format,
            includeMetadata,
            dateFormat,
            fieldSeparator: ','
          };

          // Export logs
          const exportedData = await logExplorer.exportLogs(logs, exportOptions);

          // Verify export is not empty
          expect(exportedData).toBeTruthy();
          expect(exportedData.length).toBeGreaterThan(0);

          // Verify format-specific requirements
          switch (format) {
            case 'json':
              // Should be valid JSON
              expect(() => JSON.parse(exportedData)).not.toThrow();
              const jsonData = JSON.parse(exportedData);
              expect(Array.isArray(jsonData)).toBe(true);
              expect(jsonData.length).toBe(logs.length);
              
              // Verify each entry has required fields
              for (const entry of jsonData) {
                expect(entry).toHaveProperty('id');
                expect(entry).toHaveProperty('timestamp');
                expect(entry).toHaveProperty('eventType');
                expect(entry).toHaveProperty('data');
                
                if (includeMetadata) {
                  expect(entry).toHaveProperty('metadata');
                }
              }
              break;

            case 'csv':
              // Should contain CSV headers
              const lines = exportedData.split('\n');
              expect(lines.length).toBeGreaterThan(1); // At least header + 1 data row
              
              const headers = lines[0].split(',');
              expect(headers).toContain('id');
              expect(headers).toContain('timestamp');
              expect(headers).toContain('eventType');
              
              if (includeMetadata) {
                expect(headers).toContain('processingTime');
              }
              
              // Verify data rows
              expect(lines.length - 1).toBe(logs.length); // Subtract header row
              break;

            case 'siem':
              // Should contain CEF format markers
              expect(exportedData).toContain('CEF:0|TrustLens|');
              
              const siemLines = exportedData.split('\n');
              expect(siemLines.length).toBe(logs.length);
              
              // Each line should be valid CEF format
              for (const line of siemLines) {
                expect(line).toMatch(/^CEF:0\|TrustLens\|AI Security Platform\|1\.0\|/);
              }
              break;
          }
        }
      ),
      { numRuns: 20 }
    );
  });

  /**
   * Property: Pagination works correctly
   * For any set of logs and pagination parameters, the pagination should
   * return the correct subset of results
   */
  it('should paginate results correctly for any valid pagination parameters', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(auditLogEntryArb, { minLength: 10, maxLength: 100 }),
        fc.integer({ min: 1, max: 10 }), // page
        fc.integer({ min: 5, max: 20 }), // pageSize
        async (logs, page, pageSize) => {
          // Load logs into explorer
          await logExplorer.loadLogs(logs);

          // Apply filter with pagination
          const result = await logExplorer.filterLogs({}, page, pageSize);

          // Verify pagination metadata
          expect(result.totalCount).toBe(logs.length);
          expect(result.filteredCount).toBe(logs.length); // No filter applied
          expect(result.pagination.page).toBe(page);
          expect(result.pagination.pageSize).toBe(pageSize);
          expect(result.pagination.totalPages).toBe(Math.ceil(logs.length / pageSize));

          // Verify returned logs count
          const expectedLogsCount = Math.min(pageSize, Math.max(0, logs.length - (page - 1) * pageSize));
          expect(result.logs.length).toBe(expectedLogsCount);

          // Verify logs are sorted by timestamp (newest first)
          for (let i = 1; i < result.logs.length; i++) {
            expect(result.logs[i - 1].timestamp.getTime()).toBeGreaterThanOrEqual(
              result.logs[i].timestamp.getTime()
            );
          }
        }
      ),
      { numRuns: 25 }
    );
  });

  /**
   * Property: Statistics generation is accurate
   * For any set of logs, the generated statistics should accurately
   * reflect the log data
   */
  it('should generate accurate statistics for any set of logs', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(auditLogEntryArb, { minLength: 5, maxLength: 50 }),
        async (logs) => {
          // Load logs into explorer
          await logExplorer.loadLogs(logs);

          // Generate statistics
          const stats = await logExplorer.generateLogStatistics();

          // Verify basic statistics
          expect(stats.totalLogs).toBe(logs.length);
          expect(stats.timeRange.earliest).toBeInstanceOf(Date);
          expect(stats.timeRange.latest).toBeInstanceOf(Date);
          expect(stats.timeRange.earliest.getTime()).toBeLessThanOrEqual(stats.timeRange.latest.getTime());

          // Verify event type distribution
          const actualEventTypes = logs.reduce((acc, log) => {
            acc[log.eventType] = (acc[log.eventType] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);

          for (const [eventType, count] of Object.entries(actualEventTypes)) {
            expect(stats.eventTypeDistribution[eventType]).toBe(count);
          }

          // Verify decision distribution (for logs with decisions)
          const logsWithDecisions = logs.filter(log => log.data.decision);
          const actualDecisions = logsWithDecisions.reduce((acc, log) => {
            const decision = log.data.decision!.decision;
            acc[decision] = (acc[decision] || 0) + 1;
            return acc;
          }, {} as Record<string, number>);

          for (const [decision, count] of Object.entries(actualDecisions)) {
            expect(stats.decisionDistribution[decision]).toBe(count);
          }

          // Verify average risk score calculation
          if (logsWithDecisions.length > 0) {
            const totalRiskScore = logsWithDecisions.reduce((sum, log) => sum + log.data.decision!.riskScore, 0);
            const expectedAverage = totalRiskScore / logsWithDecisions.length;
            expect(Math.abs(stats.averageRiskScore - expectedAverage)).toBeLessThan(0.01);
          } else {
            expect(stats.averageRiskScore).toBe(0);
          }

          // Verify top users
          expect(Array.isArray(stats.topUsers)).toBe(true);
          expect(stats.topUsers.length).toBeLessThanOrEqual(10);
          
          // Verify top users are sorted by count (descending)
          for (let i = 1; i < stats.topUsers.length; i++) {
            const prevCount = Number(stats.topUsers[i - 1].count);
            const currCount = Number(stats.topUsers[i].count);
            expect(prevCount).toBeGreaterThanOrEqual(currCount);
          }
        }
      ),
      { numRuns: 20 }
    );
  });

  /**
   * Property: SOC formatting is consistent
   * For any log entry, the SOC formatting should produce consistent,
   * readable output with all required fields
   */
  it('should format logs consistently for SOC display', async () => {
    await fc.assert(
      fc.asyncProperty(
        auditLogEntryArb,
        async (log) => {
          // Load single log
          await logExplorer.loadLogs([log]);

          // Format for SOC
          const socFormatted = logExplorer.formatLogForSOC(log);

          // Verify SOC format contains expected elements
          expect(socFormatted).toBeTruthy();
          expect(typeof socFormatted).toBe('string');
          expect(socFormatted.length).toBeGreaterThan(0);

          // Should contain timestamp
          expect(socFormatted).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/);

          // Should contain event type
          expect(socFormatted).toContain(log.eventType);

          // Should contain user ID or 'anonymous'
          const expectedUserId = log.userId || 'anonymous';
          expect(socFormatted).toContain(expectedUserId.substring(0, 10));

          // If there's a decision, should contain decision and risk score
          if (log.data.decision) {
            expect(socFormatted).toContain(log.data.decision.decision);
            expect(socFormatted).toContain(log.data.decision.riskScore.toString());
          }
        }
      ),
      { numRuns: 30 }
    );
  });
});