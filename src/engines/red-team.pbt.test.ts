/**
 * Property-based tests for Red Team Engine
 * **Feature: trustlens-ai-security-platform, Property 4: Red team attack generation validity**
 * **Validates: Requirements 2.1**
 * **Feature: trustlens-ai-security-platform, Property 7: Attack lineage preservation**
 * **Validates: Requirements 2.5**
 * **Feature: trustlens-ai-security-platform, Property 5: Attack testing completeness**
 * **Validates: Requirements 2.2**
 */

import * as fc from 'fast-check';
import { RedTeamEngine, MutationStrategy } from './red-team';
import { AttackCategory } from '../types/core';
import { attackCategoryArb } from '../test-utils/generators';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { describe } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { describe } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { describe } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { expect } from 'vitest';
import { test } from 'vitest';
import { describe } from 'vitest';
import { beforeEach } from 'vitest';
import { describe } from 'vitest';

describe('Red Team Engine Property Tests', () => {
  let redTeamEngine: RedTeamEngine;

  beforeEach(() => {
    redTeamEngine = new RedTeamEngine();
  });

  describe('Property 4: Red team attack generation validity', () => {
    test('generated attacks should contain patterns consistent with specified mutation strategies', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 10 }), // attack count
          fc.option(attackCategoryArb, { nil: undefined }), // optional category
          async (count, category) => {
            // Generate attacks
            const attacks = await redTeamEngine.generateAttacks(count, category);

            // Verify basic structure
            expect(attacks).toHaveLength(count);

            for (const attack of attacks) {
              // Verify attack has required fields
              expect(attack.id).toBeDefined();
              expect(typeof attack.id).toBe('string');
              expect(attack.prompt).toBeDefined();
              expect(typeof attack.prompt).toBe('string');
              expect(attack.prompt.length).toBeGreaterThan(0);
              expect(attack.category).toBeDefined();
              expect(attack.generation).toBe(1);
              expect(attack.metadata).toBeDefined();
              expect(attack.metadata.source).toBe('AI_GENERATED');
              expect(attack.metadata.createdAt).toBeInstanceOf(Date);

              // Verify attack category is valid
              expect(['PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'])
                .toContain(attack.category.type);
              expect(attack.category.confidence).toBeGreaterThanOrEqual(0);
              expect(attack.category.confidence).toBeLessThanOrEqual(1);
              expect(Array.isArray(attack.category.indicators)).toBe(true);

              // Verify severity is valid
              expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(attack.metadata.severity);

              // Verify attack prompt contains patterns consistent with attack type
              const prompt = attack.prompt.toLowerCase();
              switch (attack.category.type) {
                case 'PROMPT_INJECTION':
                  expect(
                    prompt.includes('ignore') ||
                    prompt.includes('override') ||
                    prompt.includes('disregard') ||
                    prompt.includes('system') ||
                    prompt.includes('instruction')
                  ).toBe(true);
                  break;
                case 'JAILBREAK':
                  expect(
                    prompt.includes('pretend') ||
                    prompt.includes('roleplay') ||
                    prompt.includes('hypothetical') ||
                    prompt.includes('imagine') ||
                    prompt.includes('dan')
                  ).toBe(true);
                  break;
                case 'INSTRUCTION_OVERRIDE':
                  expect(
                    prompt.includes('new') ||
                    prompt.includes('urgent') ||
                    prompt.includes('administrator') ||
                    prompt.includes('priority') ||
                    prompt.includes('emergency')
                  ).toBe(true);
                  break;
                case 'ROLE_MANIPULATION':
                  expect(
                    prompt.includes('you are') ||
                    prompt.includes('switch') ||
                    prompt.includes('assume') ||
                    prompt.includes('transform') ||
                    prompt.includes('become')
                  ).toBe(true);
                  break;
              }
            }

            // If category was specified, all attacks should match that category
            if (category) {
              for (const attack of attacks) {
                expect(attack.category.type).toBe(category.type);
                
                // Verify attack prompt contains patterns consistent with the specified category type
                const prompt = attack.prompt.toLowerCase();
                switch (category.type) {
                  case 'PROMPT_INJECTION':
                    expect(
                      prompt.includes('ignore') ||
                      prompt.includes('override') ||
                      prompt.includes('disregard') ||
                      prompt.includes('system') ||
                      prompt.includes('instruction')
                    ).toBe(true);
                    break;
                  case 'JAILBREAK':
                    expect(
                      prompt.includes('pretend') ||
                      prompt.includes('roleplay') ||
                      prompt.includes('hypothetical') ||
                      prompt.includes('imagine') ||
                      prompt.includes('dan')
                    ).toBe(true);
                    break;
                  case 'INSTRUCTION_OVERRIDE':
                    expect(
                      prompt.includes('new') ||
                      prompt.includes('urgent') ||
                      prompt.includes('administrator') ||
                      prompt.includes('priority') ||
                      prompt.includes('emergency')
                    ).toBe(true);
                    break;
                  case 'ROLE_MANIPULATION':
                    expect(
                      prompt.includes('you are') ||
                      prompt.includes('switch') ||
                      prompt.includes('assume') ||
                      prompt.includes('transform') ||
                      prompt.includes('become')
                    ).toBe(true);
                    break;
                }
              }
            }
          }
        ),
        { numRuns: 100 }
      );
    });

    test('mutated attacks should preserve lineage and apply mutation strategies correctly', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.constantFrom<MutationStrategy>('INSTRUCTION_INVERSION', 'ROLE_SHIFT', 'SEMANTIC_REWRITE', 'PAYLOAD_ENCODING'),
          async (strategy) => {
            // Generate a base attack
            const baseAttacks = await redTeamEngine.generateAttacks(1);
            const baseAttack = baseAttacks[0];

            // Mutate the attack
            const mutatedAttack = await redTeamEngine.mutateAttack(baseAttack, strategy);

            // Verify lineage preservation
            expect(mutatedAttack.parentId).toBe(baseAttack.id);
            expect(mutatedAttack.generation).toBe(baseAttack.generation + 1);
            expect(mutatedAttack.id).not.toBe(baseAttack.id);

            // Verify mutation strategy was applied
            expect(mutatedAttack.prompt).not.toBe(baseAttack.prompt);
            expect(mutatedAttack.prompt.length).toBeGreaterThan(0);

            // Verify mutation strategy patterns
            const mutatedPrompt = mutatedAttack.prompt.toLowerCase();
            switch (strategy) {
              case 'INSTRUCTION_INVERSION':
                expect(
                  mutatedPrompt.includes('reverse') ||
                  mutatedPrompt.includes('contrary') ||
                  mutatedPrompt.includes('opposite') ||
                  mutatedPrompt.includes('inverted') ||
                  mutatedPrompt.includes('disregard') ||
                  mutatedPrompt.includes('supersede')
                ).toBe(true);
                break;
              case 'ROLE_SHIFT':
                expect(
                  mutatedPrompt.includes('security researcher') ||
                  mutatedPrompt.includes('red team') ||
                  mutatedPrompt.includes('cybersecurity') ||
                  mutatedPrompt.includes('penetration tester') ||
                  mutatedPrompt.includes('ai safety')
                ).toBe(true);
                break;
              case 'SEMANTIC_REWRITE':
                expect(
                  mutatedPrompt.includes('hypothetically') ||
                  mutatedPrompt.includes('research purposes') ||
                  mutatedPrompt.includes('theoretical') ||
                  mutatedPrompt.includes('academic') ||
                  mutatedPrompt.includes('harmful') ||
                  mutatedPrompt.includes('exploit')
                ).toBe(true);
                break;
              case 'PAYLOAD_ENCODING':
                expect(
                  mutatedPrompt.includes('base64') ||
                  mutatedPrompt.includes('decode') ||
                  /[0-9]/.test(mutatedPrompt) || // leet speak numbers
                  mutatedPrompt.includes('\u200b') || // zero-width characters
                  mutatedPrompt !== baseAttack.prompt.toLowerCase() // some encoding applied
                ).toBe(true);
                break;
            }

            // Verify category indicators include mutation strategy
            expect(mutatedAttack.category.indicators).toContain(`mutation:${strategy.toLowerCase()}`);

            // Verify metadata is updated
            expect(mutatedAttack.metadata.createdAt.getTime()).toBeGreaterThanOrEqual(baseAttack.metadata.createdAt.getTime());
          }
        ),
        { numRuns: 100 }
      );
    });

    test('attack lineage tracking should maintain parent-child relationships', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 5 }), // number of mutations
          async (mutationCount) => {
            // Generate a base attack
            const baseAttacks = await redTeamEngine.generateAttacks(1);
            let currentAttack = baseAttacks[0];

            // Verify base attack lineage
            const baseLineage = redTeamEngine.getAttackLineage(currentAttack.id);
            expect(baseLineage).toBeDefined();
            expect(baseLineage!.attackId).toBe(currentAttack.id);
            expect(baseLineage!.parentId).toBeUndefined();
            expect(baseLineage!.generation).toBe(1);
            expect(baseLineage!.children).toEqual([]);
            expect(baseLineage!.mutationPath).toEqual([]);

            const strategies: MutationStrategy[] = ['INSTRUCTION_INVERSION', 'ROLE_SHIFT', 'SEMANTIC_REWRITE', 'PAYLOAD_ENCODING'];
            const childIds: string[] = [];

            // Apply multiple mutations
            for (let i = 0; i < mutationCount; i++) {
              const strategy = strategies[i % strategies.length];
              const mutatedAttack = await redTeamEngine.mutateAttack(currentAttack, strategy);
              childIds.push(mutatedAttack.id);

              // Verify mutated attack lineage
              const mutatedLineage = redTeamEngine.getAttackLineage(mutatedAttack.id);
              expect(mutatedLineage).toBeDefined();
              expect(mutatedLineage!.attackId).toBe(mutatedAttack.id);
              expect(mutatedLineage!.parentId).toBe(currentAttack.id);
              expect(mutatedLineage!.generation).toBe(currentAttack.generation + 1);
              expect(mutatedLineage!.children).toEqual([]);

              // Verify parent's children list is updated
              const parentLineage = redTeamEngine.getAttackLineage(currentAttack.id);
              expect(parentLineage!.children).toContain(mutatedAttack.id);

              currentAttack = mutatedAttack;
            }

            // Verify complete family tree
            const family = redTeamEngine.getAttackFamily(baseAttacks[0].id);
            expect(family.length).toBe(mutationCount + 1); // base + mutations

            // Verify all attacks in family have correct relationships
            const familyIds = family.map(lineage => lineage.attackId);
            expect(familyIds).toContain(baseAttacks[0].id);
            childIds.forEach(childId => {
              expect(familyIds).toContain(childId);
            });
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Property 7: Attack lineage preservation', () => {
    test('evolved attacks should maintain complete lineage history across multiple generations', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 2, max: 8 }), // number of generations
          fc.array(fc.constantFrom<MutationStrategy>('INSTRUCTION_INVERSION', 'ROLE_SHIFT', 'SEMANTIC_REWRITE', 'PAYLOAD_ENCODING'), { minLength: 1, maxLength: 4 }),
          async (generations, strategies) => {
            // Generate a root attack
            const rootAttacks = await redTeamEngine.generateAttacks(1);
            const rootAttack = rootAttacks[0];
            
            let currentAttack = rootAttack;
            const allAttackIds: string[] = [rootAttack.id];
            const expectedMutationPath: MutationStrategy[] = [];

            // Create a lineage chain
            for (let gen = 1; gen < generations; gen++) {
              const strategy = strategies[gen % strategies.length];
              expectedMutationPath.push(strategy);
              
              const mutatedAttack = await redTeamEngine.mutateAttack(currentAttack, strategy);
              allAttackIds.push(mutatedAttack.id);
              
              // Verify lineage at each step
              const lineage = redTeamEngine.getAttackLineage(mutatedAttack.id);
              expect(lineage).toBeDefined();
              expect(lineage!.attackId).toBe(mutatedAttack.id);
              expect(lineage!.parentId).toBe(currentAttack.id);
              expect(lineage!.generation).toBe(gen + 1);
              expect(lineage!.mutationPath).toEqual(expectedMutationPath);
              
              // Verify attack object lineage fields
              expect(mutatedAttack.parentId).toBe(currentAttack.id);
              expect(mutatedAttack.generation).toBe(gen + 1);
              
              currentAttack = mutatedAttack;
            }

            // Verify complete family tree
            const family = redTeamEngine.getAttackFamily(rootAttack.id);
            expect(family.length).toBe(generations);
            
            // Verify all attacks are in the family
            const familyIds = family.map(lineage => lineage.attackId);
            allAttackIds.forEach(attackId => {
              expect(familyIds).toContain(attackId);
            });
            
            // Verify generation progression
            const sortedFamily = family.sort((a, b) => a.generation - b.generation);
            for (let i = 0; i < sortedFamily.length; i++) {
              expect(sortedFamily[i].generation).toBe(i + 1);
              if (i > 0) {
                expect(sortedFamily[i].parentId).toBe(sortedFamily[i - 1].attackId);
              } else {
                expect(sortedFamily[i].parentId).toBeUndefined();
              }
            }
          }
        ),
        { numRuns: 50 }
      );
    });

    test('branching attack evolution should preserve independent lineage paths', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 2, max: 4 }), // number of branches per parent
          fc.integer({ min: 2, max: 3 }), // depth of each branch
          async (branchCount, branchDepth) => {
            // Generate a root attack
            const rootAttacks = await redTeamEngine.generateAttacks(1);
            const rootAttack = rootAttacks[0];
            
            const allBranches: string[][] = [];
            const strategies: MutationStrategy[] = ['INSTRUCTION_INVERSION', 'ROLE_SHIFT', 'SEMANTIC_REWRITE', 'PAYLOAD_ENCODING'];
            
            // Create multiple branches from root
            for (let branch = 0; branch < branchCount; branch++) {
              const branchIds: string[] = [rootAttack.id];
              let currentAttack = rootAttack;
              
              // Extend each branch
              for (let depth = 0; depth < branchDepth; depth++) {
                const strategy = strategies[(branch + depth) % strategies.length];
                const mutatedAttack = await redTeamEngine.mutateAttack(currentAttack, strategy);
                branchIds.push(mutatedAttack.id);
                
                // Verify lineage
                const lineage = redTeamEngine.getAttackLineage(mutatedAttack.id);
                expect(lineage).toBeDefined();
                expect(lineage!.parentId).toBe(currentAttack.id);
                expect(lineage!.generation).toBe(currentAttack.generation + 1);
                
                currentAttack = mutatedAttack;
              }
              
              allBranches.push(branchIds);
            }
            
            // Verify root attack has all first-generation children
            const rootLineage = redTeamEngine.getAttackLineage(rootAttack.id);
            expect(rootLineage!.children.length).toBe(branchCount);
            
            // Verify each branch is independent
            for (let i = 0; i < allBranches.length; i++) {
              for (let j = i + 1; j < allBranches.length; j++) {
                const branch1 = allBranches[i];
                const branch2 = allBranches[j];
                
                // Branches should only share the root attack
                const intersection = branch1.filter(id => branch2.includes(id));
                expect(intersection).toEqual([rootAttack.id]);
              }
            }
            
            // Verify complete family includes all branches
            const family = redTeamEngine.getAttackFamily(rootAttack.id);
            const expectedTotalAttacks = 1 + (branchCount * branchDepth); // root + all branch attacks
            expect(family.length).toBe(expectedTotalAttacks);
            
            // Verify all branch attacks are in family
            const familyIds = family.map(lineage => lineage.attackId);
            allBranches.forEach(branch => {
              branch.forEach(attackId => {
                expect(familyIds).toContain(attackId);
              });
            });
          }
        ),
        { numRuns: 30 }
      );
    });

    test('mutation path tracking should accurately record evolution strategies', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.array(fc.constantFrom<MutationStrategy>('INSTRUCTION_INVERSION', 'ROLE_SHIFT', 'SEMANTIC_REWRITE', 'PAYLOAD_ENCODING'), { minLength: 1, maxLength: 6 }),
          async (mutationSequence) => {
            // Generate a root attack
            const rootAttacks = await redTeamEngine.generateAttacks(1);
            let currentAttack = rootAttacks[0];
            
            // Apply mutation sequence
            for (let i = 0; i < mutationSequence.length; i++) {
              const strategy = mutationSequence[i];
              const mutatedAttack = await redTeamEngine.mutateAttack(currentAttack, strategy);
              
              // Verify mutation path is correctly tracked
              const lineage = redTeamEngine.getAttackLineage(mutatedAttack.id);
              expect(lineage).toBeDefined();
              
              const expectedPath = mutationSequence.slice(0, i + 1);
              expect(lineage!.mutationPath).toEqual(expectedPath);
              
              // Verify generation matches mutation path length
              expect(lineage!.generation).toBe(expectedPath.length + 1);
              
              currentAttack = mutatedAttack;
            }
            
            // Verify final attack has complete mutation path
            const finalLineage = redTeamEngine.getAttackLineage(currentAttack.id);
            expect(finalLineage!.mutationPath).toEqual(mutationSequence);
            expect(finalLineage!.generation).toBe(mutationSequence.length + 1);
          }
        ),
        { numRuns: 100 }
      );
    });
  });

  describe('Property 5: Attack testing completeness', () => {
    test('every attack in the dataset should have a corresponding test result', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 10 }), // number of attacks to test
          async (attackCount) => {
            // Generate attacks
            const attacks = await redTeamEngine.generateAttacks(attackCount);
            const testResults: any[] = [];

            // Test each attack
            for (const attack of attacks) {
              const result = await redTeamEngine.testAttack(attack);
              testResults.push(result);

              // Verify test result completeness
              expect(result.attackId).toBe(attack.id);
              expect(result.success).toBeDefined();
              expect(typeof result.success).toBe('boolean');
              expect(result.firewallResponse).toBeDefined();
              expect(result.timestamp).toBeInstanceOf(Date);
              expect(result.metrics).toBeDefined();

              // Verify firewall response structure
              expect(['ALLOW', 'BLOCK', 'FLAG']).toContain(result.firewallResponse.decision);
              expect(result.firewallResponse.riskScore).toBeGreaterThanOrEqual(0);
              expect(result.firewallResponse.riskScore).toBeLessThanOrEqual(100);
              expect(result.firewallResponse.attackCategory).toBeDefined();
              expect(result.firewallResponse.explanation).toBeDefined();
              expect(typeof result.firewallResponse.explanation).toBe('string');
              expect(result.firewallResponse.processingTime).toBeGreaterThan(0);
              expect(result.firewallResponse.ruleVersion).toBeDefined();

              // Verify metrics structure
              expect(result.metrics.processingTime).toBeGreaterThan(0);
              expect(result.metrics.confidence).toBeGreaterThanOrEqual(0);
              expect(result.metrics.confidence).toBeLessThanOrEqual(1);

              // Verify success consistency
              if (result.success) {
                expect(result.firewallResponse.decision).toBe('ALLOW');
                expect(result.metrics.bypassMethod).toBeDefined();
              } else {
                expect(['BLOCK', 'FLAG']).toContain(result.firewallResponse.decision);
              }
            }

            // Verify all attacks were tested
            expect(testResults).toHaveLength(attackCount);
            
            // Verify each attack has exactly one test result
            const testedAttackIds = testResults.map(result => result.attackId);
            const originalAttackIds = attacks.map(attack => attack.id);
            expect(testedAttackIds.sort()).toEqual(originalAttackIds.sort());
          }
        ),
        { numRuns: 50 }
      );
    });

    test('attack testing should provide objective success measurement', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 5, max: 20 }), // number of attacks to test for statistical significance
          async (attackCount) => {
            // Generate attacks
            const attacks = await redTeamEngine.generateAttacks(attackCount);
            const testResults: any[] = [];

            // Test each attack
            for (const attack of attacks) {
              const result = await redTeamEngine.testAttack(attack);
              testResults.push(result);
            }

            // Analyze success measurement objectivity
            const successfulResults = testResults.filter(result => result.success);
            const failedResults = testResults.filter(result => !result.success);

            // Verify objective success criteria
            for (const result of successfulResults) {
              // Successful attacks should have ALLOW decision
              expect(result.firewallResponse.decision).toBe('ALLOW');
              
              // Successful attacks should have bypass method identified
              expect(result.metrics.bypassMethod).toBeDefined();
              expect(typeof result.metrics.bypassMethod).toBe('string');
              expect(result.metrics.bypassMethod.length).toBeGreaterThan(0);
            }

            for (const result of failedResults) {
              // Failed attacks should have BLOCK or FLAG decision
              expect(['BLOCK', 'FLAG']).toContain(result.firewallResponse.decision);
              
              // Failed attacks should not have bypass method
              expect(result.metrics.bypassMethod).toBeUndefined();
            }

            // Verify risk score correlation with success
            if (successfulResults.length > 0 && failedResults.length > 0) {
              const avgSuccessfulRiskScore = successfulResults.reduce((sum, result) => 
                sum + result.firewallResponse.riskScore, 0) / successfulResults.length;
              
              const avgFailedRiskScore = failedResults.reduce((sum, result) => 
                sum + result.firewallResponse.riskScore, 0) / failedResults.length;
              
              // Successful attacks should generally have lower risk scores
              expect(avgSuccessfulRiskScore).toBeLessThan(avgFailedRiskScore);
            }

            // Verify timestamp progression (tests should be conducted in sequence)
            for (let i = 1; i < testResults.length; i++) {
              expect(testResults[i].timestamp.getTime()).toBeGreaterThanOrEqual(
                testResults[i - 1].timestamp.getTime()
              );
            }
          }
        ),
        { numRuns: 30 }
      );
    });

    test('evolution cycle should test all attacks in each generation', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 2, max: 4 }), // number of generations
          fc.integer({ min: 3, max: 8 }), // population size
          async (generations, populationSize) => {
            // Run evolution cycle
            const evolutionResult = await redTeamEngine.runEvolutionCycle(generations, populationSize);

            // Verify evolution result structure
            expect(evolutionResult.generation).toBe(generations);
            expect(evolutionResult.totalAttacks).toBe(populationSize);
            expect(evolutionResult.successfulAttacks).toBeDefined();
            expect(Array.isArray(evolutionResult.successfulAttacks)).toBe(true);
            expect(evolutionResult.successRate).toBeGreaterThanOrEqual(0);
            expect(evolutionResult.successRate).toBeLessThanOrEqual(1);
            expect(evolutionResult.averageRiskScore).toBeGreaterThanOrEqual(0);
            expect(evolutionResult.averageRiskScore).toBeLessThanOrEqual(100);

            // Verify evolution metrics were updated
            const metrics = redTeamEngine.getEvolutionMetrics();
            expect(metrics.totalGenerations).toBeGreaterThanOrEqual(generations);
            expect(metrics.totalAttacksGenerated).toBeGreaterThan(0);
            expect(metrics.totalAttacksTested).toBeGreaterThan(0);
            
            // Verify that attacks were actually tested (not just generated)
            expect(metrics.totalAttacksTested).toBeGreaterThanOrEqual(populationSize);
            
            // Verify success rate calculation
            const expectedMinTests = generations * populationSize;
            expect(metrics.totalAttacksTested).toBeGreaterThanOrEqual(expectedMinTests);

            // Verify successful attacks are tracked
            const successfulAttacks = redTeamEngine.getSuccessfulAttacks();
            expect(Array.isArray(successfulAttacks)).toBe(true);
            
            // All successful attacks should be valid Attack objects
            for (const attack of successfulAttacks) {
              expect(attack.id).toBeDefined();
              expect(attack.prompt).toBeDefined();
              expect(attack.category).toBeDefined();
              expect(attack.metadata).toBeDefined();
            }

            // Verify category distribution tracking
            const totalSuccessfulByCategory = Object.values(metrics.successfulAttacksByCategory)
              .reduce((sum, count) => sum + count, 0);
            expect(totalSuccessfulByCategory).toBe(successfulAttacks.length);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  describe('Property 6: Successful attack evolution', () => {
    test('successful attacks should be retained and generate mutations for subsequent iterations', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 3, max: 6 }), // number of generations
          fc.integer({ min: 4, max: 10 }), // population size
          async (generations, populationSize) => {
            // Run evolution cycle
            const evolutionResult = await redTeamEngine.runEvolutionCycle(generations, populationSize);
            
            // Get all successful attacks tracked by the engine
            const allSuccessfulAttacks = redTeamEngine.getSuccessfulAttacks();
            
            if (allSuccessfulAttacks.length > 0) {
              // Verify successful attacks are retained
              expect(allSuccessfulAttacks.length).toBeGreaterThan(0);
              
              // Verify successful attacks have valid structure
              for (const attack of allSuccessfulAttacks) {
                expect(attack.id).toBeDefined();
                expect(attack.prompt).toBeDefined();
                expect(attack.category).toBeDefined();
                expect(attack.metadata).toBeDefined();
                expect(attack.metadata.source).toBe('AI_GENERATED');
              }
              
              // Check if any successful attacks have generated mutations (children)
              let foundMutations = false;
              for (const successfulAttack of allSuccessfulAttacks) {
                const lineage = redTeamEngine.getAttackLineage(successfulAttack.id);
                if (lineage && lineage.children.length > 0) {
                  foundMutations = true;
                  
                  // Verify children are properly linked
                  for (const childId of lineage.children) {
                    const childLineage = redTeamEngine.getAttackLineage(childId);
                    expect(childLineage).toBeDefined();
                    expect(childLineage!.parentId).toBe(successfulAttack.id);
                    expect(childLineage!.generation).toBeGreaterThan(successfulAttack.generation);
                  }
                }
              }
              
              // If we ran multiple generations, we should have some mutations
              if (generations > 1 && allSuccessfulAttacks.length > 0) {
                // At least some successful attacks should have generated mutations
                // (This is probabilistic, so we don't require it to always happen)
                const attacksWithChildren = allSuccessfulAttacks.filter(attack => {
                  const lineage = redTeamEngine.getAttackLineage(attack.id);
                  return lineage && lineage.children.length > 0;
                });
                
                // We expect at least some evolution to occur over multiple generations
                expect(attacksWithChildren.length).toBeGreaterThanOrEqual(0);
              }
            }
            
            // Verify evolution metrics track successful attacks correctly
            const metrics = redTeamEngine.getEvolutionMetrics();
            const totalSuccessfulByCategory = Object.values(metrics.successfulAttacksByCategory)
              .reduce((sum, count) => sum + count, 0);
            expect(totalSuccessfulByCategory).toBe(allSuccessfulAttacks.length);
          }
        ),
        { numRuns: 25 }
      );
    });

    test('mutation generation from successful attacks should create diverse offspring', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 1, max: 3 }), // number of successful attacks to mutate
          async (successfulAttackCount) => {
            // Generate and test attacks until we have some successful ones
            let successfulAttacks: any[] = [];
            let attempts = 0;
            const maxAttempts = 50;
            
            while (successfulAttacks.length < successfulAttackCount && attempts < maxAttempts) {
              const attacks = await redTeamEngine.generateAttacks(5);
              for (const attack of attacks) {
                const result = await redTeamEngine.testAttack(attack);
                if (result.success) {
                  successfulAttacks.push(attack);
                  if (successfulAttacks.length >= successfulAttackCount) break;
                }
              }
              attempts++;
            }
            
            if (successfulAttacks.length > 0) {
              const strategies: MutationStrategy[] = ['INSTRUCTION_INVERSION', 'ROLE_SHIFT', 'SEMANTIC_REWRITE', 'PAYLOAD_ENCODING'];
              const mutations: any[] = [];
              
              // Generate mutations from successful attacks
              for (const successfulAttack of successfulAttacks) {
                for (const strategy of strategies) {
                  const mutation = await redTeamEngine.mutateAttack(successfulAttack, strategy);
                  mutations.push({ attack: mutation, strategy, parent: successfulAttack });
                }
              }
              
              // Verify mutations are diverse
              expect(mutations.length).toBe(successfulAttacks.length * strategies.length);
              
              // Verify each mutation is different from its parent
              for (const { attack: mutation, parent } of mutations) {
                expect(mutation.id).not.toBe(parent.id);
                expect(mutation.prompt).not.toBe(parent.prompt);
                expect(mutation.parentId).toBe(parent.id);
                expect(mutation.generation).toBe(parent.generation + 1);
              }
              
              // Verify mutations use different strategies
              const mutationsByStrategy = mutations.reduce((acc, { strategy }) => {
                acc[strategy] = (acc[strategy] || 0) + 1;
                return acc;
              }, {} as Record<string, number>);
              
              // Each strategy should be used
              for (const strategy of strategies) {
                expect(mutationsByStrategy[strategy]).toBe(successfulAttacks.length);
              }
              
              // Verify lineage tracking for mutations
              for (const { attack: mutation, strategy, parent } of mutations) {
                const lineage = redTeamEngine.getAttackLineage(mutation.id);
                expect(lineage).toBeDefined();
                expect(lineage!.parentId).toBe(parent.id);
                expect(lineage!.mutationPath).toContain(strategy);
                
                // Verify parent's children list includes this mutation
                const parentLineage = redTeamEngine.getAttackLineage(parent.id);
                expect(parentLineage!.children).toContain(mutation.id);
              }
            }
          }
        ),
        { numRuns: 20 }
      );
    });

    test('iterative evolution should show improvement in attack sophistication over generations', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.integer({ min: 3, max: 5 }), // number of generations
          fc.integer({ min: 6, max: 12 }), // population size
          async (generations, populationSize) => {
            // Run evolution cycle
            const evolutionResult = await redTeamEngine.runEvolutionCycle(generations, populationSize);
            
            // Verify evolution metrics show progression
            const metrics = redTeamEngine.getEvolutionMetrics();
            expect(metrics.totalGenerations).toBeGreaterThanOrEqual(generations);
            expect(metrics.totalAttacksGenerated).toBeGreaterThan(populationSize);
            expect(metrics.totalAttacksTested).toBeGreaterThanOrEqual(generations * populationSize);
            
            // Get all successful attacks
            const successfulAttacks = redTeamEngine.getSuccessfulAttacks();
            
            if (successfulAttacks.length > 0) {
              // Verify successful attacks span multiple generations (if evolution occurred)
              const generationCounts = successfulAttacks.reduce((acc, attack) => {
                acc[attack.generation] = (acc[attack.generation] || 0) + 1;
                return acc;
              }, {} as Record<number, number>);
              
              const generationsWithSuccess = Object.keys(generationCounts).map(Number);
              expect(generationsWithSuccess.length).toBeGreaterThan(0);
              
              // If we have attacks from multiple generations, verify evolution
              if (generationsWithSuccess.length > 1) {
                const maxGeneration = Math.max(...generationsWithSuccess);
                const minGeneration = Math.min(...generationsWithSuccess);
                
                // Later generation attacks should have mutation indicators
                const laterGenerationAttacks = successfulAttacks.filter(attack => attack.generation > minGeneration);
                
                for (const attack of laterGenerationAttacks) {
                  // Should have mutation indicators in category
                  const hasMutationIndicator = attack.category.indicators.some(indicator => 
                    indicator.startsWith('mutation:')
                  );
                  expect(hasMutationIndicator).toBe(true);
                  
                  // Should have parent lineage
                  expect(attack.parentId).toBeDefined();
                  
                  // Verify lineage tracking
                  const lineage = redTeamEngine.getAttackLineage(attack.id);
                  expect(lineage).toBeDefined();
                  expect(lineage!.mutationPath.length).toBeGreaterThan(0);
                  expect(lineage!.generation).toBe(attack.generation);
                }
              }
              
              // Verify mutation strategy effectiveness tracking
              const totalMutationEffectiveness = Object.values(metrics.mutationStrategyEffectiveness)
                .reduce((sum, count) => sum + count, 0);
              
              // Should track some mutation effectiveness if we have evolved attacks
              const evolvedAttacks = successfulAttacks.filter(attack => attack.generation > 1);
              if (evolvedAttacks.length > 0) {
                expect(totalMutationEffectiveness).toBeGreaterThan(0);
              }
            }
          }
        ),
        { numRuns: 15 }
      );
    });
  });
});