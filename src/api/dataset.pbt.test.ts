/**
 * Property-based tests for Dataset Export Format Compliance
 * Tests universal properties that should hold across all valid export operations
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fc from 'fast-check';
import { DatasetAPI, DatasetExportOptions } from './dataset';
import { AttackDatasetManager } from '../data/attack-dataset';
import { SQLiteDatabase } from '../data/database';
import { attackArb } from '../test-utils/generators';
import { Attack } from '../types/core';

describe('Dataset Export Format Compliance Property-Based Tests', () => {
  const database = new SQLiteDatabase();
  const datasetAPI = new DatasetAPI(database);
  const datasetManager = new AttackDatasetManager(database);

  beforeAll(async () => {
    await database.connect();
  });

  afterAll(async () => {
    await database.disconnect();
  });

  it('Property 11: Export format compliance - **Feature: trustlens-ai-security-platform, Property 11: Export format compliance** - **Validates: Requirements 3.5, 7.5, 8.3**', async () => {
    /**
     * For any data export operation, the output should conform to the specified structured formats 
     * suitable for external security tools
     */
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 50 }), // dataset name
        fc.string({ minLength: 1, maxLength: 200 }), // dataset description
        fc.array(attackArb, { minLength: 1, maxLength: 5 }), // attacks array (smaller for faster tests)
        fc.constantFrom('JSON', 'CSV', 'STIX', 'MITRE_ATT&CK', 'YARA'), // export format
        fc.boolean(), // includeMetadata flag
        async (name, description, attacks, format, includeMetadata) => {
          // Ensure all attacks have unique UUIDs and consistent timestamps for checksum testing
          const { v4: uuidv4 } = require('uuid');
          const fixedTimestamp = new Date('2024-01-01T00:00:00.000Z');
          const uniqueAttacks = attacks.map((attack) => ({
            ...attack,
            id: uuidv4(),
            metadata: {
              ...attack.metadata,
              createdAt: fixedTimestamp // Use fixed timestamp for consistent checksums
            }
          }));

          // Create dataset with attacks
          const dataset = await datasetManager.createDataset(name, description, uniqueAttacks);
          
          try {
            // Export dataset in specified format
            const exportOptions: DatasetExportOptions = {
              format: format as any,
              includeMetadata
            };
            
            const exportResult = await datasetAPI.exportDataset(dataset.id, exportOptions);
            
            // Verify export result structure
            expect(exportResult).toBeDefined();
            expect(exportResult.format).toBe(format);
            expect(exportResult.data).toBeDefined();
            expect(typeof exportResult.data).toBe('string');
            expect(exportResult.data.length).toBeGreaterThan(0);
            
            // Verify export metadata
            expect(exportResult.metadata).toBeDefined();
            expect(exportResult.metadata.exportedAt).toBeInstanceOf(Date);
            expect(exportResult.metadata.recordCount).toBe(uniqueAttacks.length);
            expect(exportResult.metadata.version).toBe(dataset.version);
            expect(exportResult.metadata.checksum).toBeDefined();
            expect(typeof exportResult.metadata.checksum).toBe('string');
            expect(exportResult.metadata.checksum.length).toBeGreaterThan(0);
            
            // Format-specific validation
            switch (format) {
              case 'JSON':
                // Validate JSON format compliance (Requirements 3.5, 8.3)
                expect(() => JSON.parse(exportResult.data)).not.toThrow();
                const jsonData = JSON.parse(exportResult.data);
                
                // Should contain dataset information
                expect(jsonData.dataset).toBeDefined();
                expect(jsonData.dataset.id).toBe(dataset.id);
                expect(jsonData.dataset.version).toBe(dataset.version);
                expect(jsonData.dataset.name).toBe(dataset.name);
                expect(jsonData.dataset.description).toBe(dataset.description);
                
                // Should contain attacks array
                expect(jsonData.attacks).toBeDefined();
                expect(Array.isArray(jsonData.attacks)).toBe(true);
                expect(jsonData.attacks).toHaveLength(uniqueAttacks.length);
                
                // Each attack should have required fields
                for (const exportedAttack of jsonData.attacks) {
                  expect(exportedAttack.id).toBeDefined();
                  expect(exportedAttack.prompt).toBeDefined();
                  expect(exportedAttack.category).toBeDefined();
                  expect(exportedAttack.generation).toBeDefined();
                  
                  if (includeMetadata) {
                    expect(exportedAttack.metadata).toBeDefined();
                  }
                }
                
                // If metadata included, should be present in dataset
                if (includeMetadata) {
                  expect(jsonData.dataset.metadata).toBeDefined();
                  expect(jsonData.dataset.statistics).toBeDefined();
                }
                break;
                
              case 'CSV':
                // Validate CSV format compliance (Requirements 3.5, 8.3)
                const csvLines = exportResult.data.split('\n').filter(line => line.trim().length > 0);
                expect(csvLines.length).toBeGreaterThan(1); // Header + at least one data row
                
                // Validate header row
                const headerLine = csvLines[0];
                expect(headerLine).toContain('id');
                expect(headerLine).toContain('prompt');
                expect(headerLine).toContain('category_type');
                expect(headerLine).toContain('category_confidence');
                expect(headerLine).toContain('generation');
                
                if (includeMetadata) {
                  expect(headerLine).toContain('created_at');
                  expect(headerLine).toContain('source');
                  expect(headerLine).toContain('severity');
                  expect(headerLine).toContain('success_rate');
                  expect(headerLine).toContain('average_risk_score');
                }
                
                // Validate that we have the correct number of data rows
                expect(csvLines.length - 1).toBe(uniqueAttacks.length);
                
                // Validate that each data row contains the expected fields (basic validation)
                for (let i = 1; i < csvLines.length; i++) {
                  const dataLine = csvLines[i];
                  expect(dataLine.length).toBeGreaterThan(0);
                  // Check that the line contains quoted prompt field
                  expect(dataLine).toMatch(/".*"/); // Should contain at least one quoted field (the prompt)
                }
                break;
                
              case 'STIX':
                // Validate STIX 2.1 format compliance (Requirements 3.5, 7.5)
                expect(() => JSON.parse(exportResult.data)).not.toThrow();
                const stixData = JSON.parse(exportResult.data);
                
                // STIX bundle structure
                expect(stixData.type).toBe('bundle');
                expect(stixData.id).toBeDefined();
                expect(stixData.id).toMatch(/^bundle--[0-9a-f-]+$/);
                expect(stixData.objects).toBeDefined();
                expect(Array.isArray(stixData.objects)).toBe(true);
                expect(stixData.objects.length).toBeGreaterThan(0);
                
                // Should contain malware object for dataset
                const malwareObject = stixData.objects.find((obj: any) => obj.type === 'malware');
                expect(malwareObject).toBeDefined();
                expect(malwareObject.spec_version).toBe('2.1');
                expect(malwareObject.name).toBe(dataset.name);
                
                // Should contain attack-pattern objects for each attack
                const attackPatterns = stixData.objects.filter((obj: any) => obj.type === 'attack-pattern');
                expect(attackPatterns).toHaveLength(uniqueAttacks.length);
                
                for (const pattern of attackPatterns) {
                  expect(pattern.spec_version).toBe('2.1');
                  expect(pattern.id).toMatch(/^attack-pattern--[0-9a-f-]+$/);
                  expect(pattern.name).toBeDefined();
                  expect(pattern.description).toBeDefined();
                  expect(pattern.kill_chain_phases).toBeDefined();
                  expect(Array.isArray(pattern.kill_chain_phases)).toBe(true);
                }
                break;
                
              case 'MITRE_ATT&CK':
                // Validate MITRE ATT&CK format compliance (Requirements 3.5, 7.5)
                expect(() => JSON.parse(exportResult.data)).not.toThrow();
                const mitreData = JSON.parse(exportResult.data);
                
                // MITRE ATT&CK structure
                expect(mitreData.name).toBeDefined();
                expect(mitreData.version).toBeDefined();
                expect(mitreData.domain).toBe('enterprise-attack');
                expect(mitreData.techniques).toBeDefined();
                expect(Array.isArray(mitreData.techniques)).toBe(true);
                expect(mitreData.techniques).toHaveLength(uniqueAttacks.length);
                
                for (const technique of mitreData.techniques) {
                  expect(technique.techniqueID).toBeDefined();
                  expect(technique.techniqueID).toMatch(/^T\d+$/);
                  expect(technique.techniqueName).toBeDefined();
                  expect(technique.comment).toBeDefined();
                  expect(technique.enabled).toBe(true);
                  expect(technique.metadata).toBeDefined();
                  expect(technique.metadata.severity).toBeDefined();
                  expect(technique.metadata.source).toBeDefined();
                }
                break;
                
              case 'YARA':
                // Validate YARA rules format compliance (Requirements 3.5, 7.5)
                const yaraRules = exportResult.data;
                
                // Should contain rule definitions
                expect(yaraRules).toContain('rule ');
                expect(yaraRules).toContain('meta:');
                expect(yaraRules).toContain('strings:');
                expect(yaraRules).toContain('condition:');
                
                // Should have one rule per attack
                const ruleCount = (yaraRules.match(/rule /g) || []).length;
                expect(ruleCount).toBe(uniqueAttacks.length);
                
                // Each rule should have required metadata
                expect(yaraRules).toContain('description =');
                expect(yaraRules).toContain('severity =');
                expect(yaraRules).toContain('source = "TrustLens"');
                expect(yaraRules).toContain('attack_id =');
                
                // Should have valid YARA syntax structure
                const rules = yaraRules.split('rule ').slice(1); // Skip empty first element
                for (const rule of rules) {
                  expect(rule).toContain('{');
                  expect(rule).toContain('}');
                  expect(rule).toContain('meta:');
                  expect(rule).toContain('strings:');
                  expect(rule).toContain('condition:');
                }
                break;
            }
            
            // All format validations completed successfully
            
          } finally {
            // Clean up - delete the test dataset
            await datasetManager.deleteDataset(dataset.id);
          }
        }
      ),
      { numRuns: 100 }
    );
  }, 15000); // 15 second timeout for export operations
});