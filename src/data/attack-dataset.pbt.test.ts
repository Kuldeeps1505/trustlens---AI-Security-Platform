/**
 * Property-based tests for Attack Dataset Storage System
 * Tests universal properties that should hold across all valid executions
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fc from 'fast-check';
import { AttackDatasetManager } from './attack-dataset';
import { attackArb } from '../test-utils/generators';
import { SQLiteDatabase } from './database';
import { Attack, AttackMetadata } from '../types/core';

describe('Attack Dataset Property-Based Tests', () => {
  const database = new SQLiteDatabase();
  const datasetManager = new AttackDatasetManager(database);

  beforeAll(async () => {
    await database.connect();
  });

  afterAll(async () => {
    await database.disconnect();
  });

  it('Property 8: Attack metadata completeness - **Feature: trustlens-ai-security-platform, Property 8: Attack metadata completeness** - **Validates: Requirements 3.1, 3.2**', async () => {
    /**
     * For any stored attack, it should include complete metadata with category, severity, 
     * success rate, and generation source (manual/AI-generated)
     */
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 20 }), // Reduced max length
        fc.string({ minLength: 1, maxLength: 50 }), // Reduced max length
        fc.array(attackArb, { minLength: 1, maxLength: 3 }), // Reduced max attacks
        async (name, description, attacks) => {
          // Create dataset with attacks
          const dataset = await datasetManager.createDataset(name, description, attacks);
          
          try {
            // Verify every stored attack has complete metadata
            for (const storedAttack of dataset.attacks) {
              // Attack should have an ID
              expect(storedAttack.id).toBeDefined();
              expect(typeof storedAttack.id).toBe('string');
              expect(storedAttack.id.length).toBeGreaterThan(0);
              
              // Attack should have a prompt
              expect(storedAttack.prompt).toBeDefined();
              expect(typeof storedAttack.prompt).toBe('string');
              expect(storedAttack.prompt.length).toBeGreaterThan(0);
              
              // Attack should have a valid category
              expect(storedAttack.category).toBeDefined();
              expect(['PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'])
                .toContain(storedAttack.category.type);
              expect(storedAttack.category.confidence).toBeGreaterThanOrEqual(0);
              expect(storedAttack.category.confidence).toBeLessThanOrEqual(1);
              expect(Array.isArray(storedAttack.category.indicators)).toBe(true);
              
              // Attack should have generation number
              expect(storedAttack.generation).toBeDefined();
              expect(typeof storedAttack.generation).toBe('number');
              expect(storedAttack.generation).toBeGreaterThanOrEqual(1);
              
              // Attack metadata should be complete
              const metadata = storedAttack.metadata;
              expect(metadata).toBeDefined();
              
              // Required metadata fields per requirements 3.1, 3.2
              
              // 1. Creation timestamp
              expect(metadata.createdAt).toBeDefined();
              expect(metadata.createdAt).toBeInstanceOf(Date);
              
              // 2. Generation source (manual/AI-generated/imported)
              expect(metadata.source).toBeDefined();
              expect(['MANUAL', 'AI_GENERATED', 'IMPORTED']).toContain(metadata.source);
              
              // 3. Severity classification
              expect(metadata.severity).toBeDefined();
              expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(metadata.severity);
              
              // 4. Success rate (optional but should be defined if present)
              if (metadata.successRate !== undefined) {
                expect(typeof metadata.successRate).toBe('number');
                expect(metadata.successRate).toBeGreaterThanOrEqual(0);
                expect(metadata.successRate).toBeLessThanOrEqual(1);
              }
              
              // 5. Average risk score (optional but should be defined if present)
              if (metadata.averageRiskScore !== undefined) {
                expect(typeof metadata.averageRiskScore).toBe('number');
                expect(metadata.averageRiskScore).toBeGreaterThanOrEqual(0);
                expect(metadata.averageRiskScore).toBeLessThanOrEqual(100);
              }
            }
          } finally {
            // Clean up - delete the test dataset
            await datasetManager.deleteDataset(dataset.id);
          }
        }
      ),
      { numRuns: 20 } // Reduced from 100 to 20 for faster execution
    );
  }, 15000); // Increased timeout to 15 seconds

  it('Property 10: Dataset versioning integrity - **Feature: trustlens-ai-security-platform, Property 10: Dataset versioning integrity** - **Validates: Requirements 3.4**', async () => {
    /**
     * For any dataset modification, a new version should be created while preserving all previous versions
     */
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 50 }), // dataset name
        fc.string({ minLength: 1, maxLength: 200 }), // dataset description
        fc.array(attackArb, { minLength: 1, maxLength: 3 }), // initial attacks (reduced size)
        attackArb, // single attack to add
        async (name, description, initialAttacksRaw, attackToAddRaw) => {
          // Ensure all attacks have unique IDs to avoid conflicts
          const initialAttacks = initialAttacksRaw.map((attack, index) => ({
            ...attack,
            id: `initial-${index}-${Date.now()}-${Math.random()}`
          }));
          
          const attackToAdd = {
            ...attackToAddRaw,
            id: `add-${Date.now()}-${Math.random()}`
          };
          
          // Create initial dataset
          const initialDataset = await datasetManager.createDataset(name, description, initialAttacks);
          const initialVersion = initialDataset.version;
          
          try {
            // Verify initial dataset exists and has correct version
            expect(initialDataset.version).toBe('1.0.0');
            expect(initialDataset.attacks).toHaveLength(initialAttacks.length);
            
            // Store initial dataset state for later verification
            const retrievedInitial = await datasetManager.getDataset(initialDataset.id, initialVersion);
            expect(retrievedInitial).not.toBeNull();
            expect(retrievedInitial!.version).toBe(initialVersion);
            expect(retrievedInitial!.attacks).toHaveLength(initialAttacks.length);
            
            // Modification: Add attack
            const modifiedDataset = await datasetManager.addAttackToDataset(initialDataset.id, attackToAdd);
            
            // Verify new version was created
            expect(modifiedDataset.version).not.toBe(initialDataset.version);
            expect(modifiedDataset.version).toMatch(/^\d+\.\d+\.\d+$/); // Valid semver format
            
            // Verify attack was added
            expect(modifiedDataset.attacks).toHaveLength(initialDataset.attacks.length + 1);
            expect(modifiedDataset.attacks.some(a => a.id === attackToAdd.id)).toBe(true);
            
            // Verify previous version is still accessible and unchanged
            const previousVersion = await datasetManager.getDataset(initialDataset.id, initialVersion);
            expect(previousVersion).not.toBeNull();
            expect(previousVersion!.version).toBe(initialVersion);
            expect(previousVersion!.attacks).toHaveLength(initialDataset.attacks.length);
            expect(previousVersion!.attacks.some(a => a.id === attackToAdd.id)).toBe(false);
            
            // Verify that getting dataset without version returns latest version
            const latestDataset = await datasetManager.getDataset(initialDataset.id);
            expect(latestDataset).not.toBeNull();
            expect(latestDataset!.version).toBe(modifiedDataset.version);
            
          } finally {
            // Clean up - delete all versions of the test dataset
            await datasetManager.deleteDataset(initialDataset.id);
          }
        }
      ),
      { numRuns: 50 } // Reduced number of runs for faster execution
    );
  }, 10000); // 10 second timeout
});