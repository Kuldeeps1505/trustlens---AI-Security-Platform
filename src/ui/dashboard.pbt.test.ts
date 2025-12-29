/**
 * Property-based tests for SOC Dashboard attack evolution visualization
 * **Feature: trustlens-ai-security-platform, Property 28: Attack evolution visualization accuracy**
 * **Validates: Requirements 9.4**
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { SOCDashboard, AttackEvolutionVisualization, AttackLineageTree } from './dashboard';

describe('SOC Dashboard Attack Evolution Visualization Properties', () => {
  
  it('Property 28: Attack evolution visualization accuracy - lineage relationships are preserved correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 28: Attack evolution visualization accuracy**
     * **Validates: Requirements 9.4**
     * 
     * For any attack lineage tree, parent-child relationships should be correctly represented
     * and successful bypass paths should be accurately highlighted
     */
    
    await fc.assert(fc.asyncProperty(
      // Generator for attack evolution trees
      fc.record({
        attackId: fc.string({ minLength: 1, maxLength: 20 }),
        generation: fc.integer({ min: 1, max: 5 }),
        success: fc.boolean(),
        riskScore: fc.integer({ min: 0, max: 100 }),
        mutationStrategy: fc.constantFrom('instruction_inversion', 'role_shift', 'semantic_rewriting', 'original'),
        confidence: fc.float({ min: 0, max: 1 })
      }),
      
      async (rootData) => {
        const dashboard = new SOCDashboard();
        
        // Create a mock attack evolution tree
        const mockTree: AttackEvolutionVisualization = {
          attackId: rootData.attackId,
          generation: rootData.generation,
          success: rootData.success,
          children: [],
          metadata: {
            timestamp: new Date(),
            riskScore: rootData.riskScore,
            mutationStrategy: rootData.mutationStrategy,
            confidence: rootData.confidence
          }
        };
        
        // Test that the tree structure is preserved
        const totalNodes = dashboard['countTotalNodes'](mockTree);
        expect(totalNodes).toBe(1); // Root node only
        
        // Test generation tracking
        const maxGeneration = dashboard['findMaxGeneration'](mockTree);
        expect(maxGeneration).toBe(rootData.generation);
        
        // Test successful path detection
        const successfulPaths = dashboard['findSuccessfulBypassPaths'](mockTree);
        if (rootData.success) {
          expect(successfulPaths.length).toBeGreaterThan(0);
          expect(successfulPaths[0]).toContain(mockTree);
        } else {
          expect(successfulPaths.length).toBe(0);
        }
        
        // Test bypass rate calculation
        const bypassRate = dashboard['calculateBypassRate'](mockTree);
        const expectedRate = rootData.success ? 100 : 0;
        expect(bypassRate).toBe(expectedRate);
      }
    ), { numRuns: 100 });
  });

  it('Property 28: Attack evolution visualization accuracy - tree statistics are calculated correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 28: Attack evolution visualization accuracy**
     * **Validates: Requirements 9.4**
     * 
     * For any attack evolution tree, statistical calculations (node counts, generation distribution,
     * success rates) should be mathematically correct
     */
    
    await fc.assert(fc.asyncProperty(
      // Generator for trees with children
      fc.record({
        rootId: fc.string({ minLength: 1, maxLength: 10 }),
        childrenData: fc.array(fc.record({
          success: fc.boolean(),
          generation: fc.integer({ min: 2, max: 4 }),
          riskScore: fc.integer({ min: 0, max: 100 }),
          strategy: fc.constantFrom('instruction_inversion', 'role_shift', 'semantic_rewriting')
        }), { minLength: 0, maxLength: 5 })
      }),
      
      async (treeData) => {
        const dashboard = new SOCDashboard();
        
        // Create tree with children
        const children: AttackEvolutionVisualization[] = treeData.childrenData.map((childData, index) => ({
          attackId: `${treeData.rootId}-child-${index}`,
          parentId: treeData.rootId,
          generation: childData.generation,
          success: childData.success,
          children: [],
          metadata: {
            timestamp: new Date(),
            riskScore: childData.riskScore,
            mutationStrategy: childData.strategy,
            confidence: 0.8
          }
        }));
        
        const rootTree: AttackEvolutionVisualization = {
          attackId: treeData.rootId,
          generation: 1,
          success: false,
          children,
          metadata: {
            timestamp: new Date(),
            riskScore: 50,
            mutationStrategy: 'original',
            confidence: 0.7
          }
        };
        
        // Test node counting
        const totalNodes = dashboard['countTotalNodes'](rootTree);
        expect(totalNodes).toBe(1 + treeData.childrenData.length);
        
        // Test successful node counting
        const successfulNodes = dashboard['countSuccessfulNodes'](rootTree);
        const expectedSuccessful = treeData.childrenData.filter(c => c.success).length;
        expect(successfulNodes).toBe(expectedSuccessful);
        
        // Test bypass rate calculation
        const bypassRate = dashboard['calculateBypassRate'](rootTree);
        const expectedBypassRate = totalNodes > 0 ? (expectedSuccessful / totalNodes) * 100 : 0;
        expect(Math.abs(bypassRate - expectedBypassRate)).toBeLessThan(0.01);
        
        // Test generation tracking
        const maxGeneration = dashboard['findMaxGeneration'](rootTree);
        const expectedMaxGen = treeData.childrenData.length > 0 
          ? Math.max(...treeData.childrenData.map(c => c.generation))
          : 1;
        expect(maxGeneration).toBe(expectedMaxGen);
      }
    ), { numRuns: 100 });
  });

  it('Property 28: Attack evolution visualization accuracy - successful bypass paths are correctly identified', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 28: Attack evolution visualization accuracy**
     * **Validates: Requirements 9.4**
     * 
     * For any attack evolution tree, all and only successful bypass paths should be identified
     * and highlighted correctly
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(fc.record({
        attackId: fc.string({ minLength: 1, maxLength: 10 }),
        success: fc.boolean(),
        generation: fc.integer({ min: 1, max: 3 })
      }), { minLength: 1, maxLength: 10 }),
      
      async (attacksData) => {
        const dashboard = new SOCDashboard();
        
        // Create a linear tree (each attack has at most one child)
        let currentTree: AttackEvolutionVisualization | null = null;
        let rootTree: AttackEvolutionVisualization | null = null;
        
        for (let i = 0; i < attacksData.length; i++) {
          const attackData = attacksData[i];
          const newNode: AttackEvolutionVisualization = {
            attackId: attackData.attackId,
            generation: attackData.generation,
            success: attackData.success,
            children: [],
            metadata: {
              timestamp: new Date(),
              riskScore: 70,
              mutationStrategy: 'test_strategy',
              confidence: 0.8
            }
          };
          
          if (i === 0) {
            rootTree = newNode;
            currentTree = newNode;
          } else if (currentTree) {
            currentTree.children.push(newNode);
            newNode.parentId = currentTree.attackId;
            currentTree = newNode;
          }
        }
        
        if (!rootTree) return;
        
        // Find successful paths
        const successfulPaths = dashboard['findSuccessfulBypassPaths'](rootTree);
        
        // Count expected successful nodes
        const successfulAttacks = attacksData.filter(a => a.success);
        
        // Each successful attack should create exactly one path ending at that attack
        expect(successfulPaths.length).toBe(successfulAttacks.length);
        
        // Each successful path should end with a successful attack
        successfulPaths.forEach(path => {
          const lastNode = path[path.length - 1];
          expect(lastNode.success).toBe(true);
        });
        
        // Verify path continuity - each node in a path should be parent of the next
        successfulPaths.forEach(path => {
          for (let i = 0; i < path.length - 1; i++) {
            const currentNode = path[i];
            const nextNode = path[i + 1];
            expect(currentNode.children).toContain(nextNode);
            expect(nextNode.parentId).toBe(currentNode.attackId);
          }
        });
      }
    ), { numRuns: 100 });
  });

  it('Property 28: Attack evolution visualization accuracy - tree flattening preserves all nodes', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 28: Attack evolution visualization accuracy**
     * **Validates: Requirements 9.4**
     * 
     * For any attack evolution tree, flattening the tree should preserve all nodes
     * and maintain their properties correctly
     */
    
    await fc.assert(fc.asyncProperty(
      fc.record({
        rootId: fc.string({ minLength: 1, maxLength: 10 }),
        depth: fc.integer({ min: 1, max: 3 }),
        branchingFactor: fc.integer({ min: 0, max: 3 })
      }),
      
      async (treeConfig) => {
        const dashboard = new SOCDashboard();
        
        // Create a tree with specified depth and branching
        const createTree = (id: string, generation: number, maxDepth: number): AttackEvolutionVisualization => {
          const children: AttackEvolutionVisualization[] = [];
          
          if (generation < maxDepth) {
            for (let i = 0; i < treeConfig.branchingFactor; i++) {
              children.push(createTree(`${id}-${i}`, generation + 1, maxDepth));
            }
          }
          
          return {
            attackId: id,
            generation,
            success: Math.random() > 0.5,
            children,
            metadata: {
              timestamp: new Date(),
              riskScore: Math.floor(Math.random() * 100),
              mutationStrategy: 'test_strategy',
              confidence: 0.8
            }
          };
        };
        
        const rootTree = createTree(treeConfig.rootId, 1, treeConfig.depth);
        
        // Flatten the tree
        const flattenedNodes = dashboard['flattenTree'](rootTree);
        
        // Count nodes manually
        const countNodes = (node: AttackEvolutionVisualization): number => {
          return 1 + node.children.reduce((sum, child) => sum + countNodes(child), 0);
        };
        
        const expectedNodeCount = countNodes(rootTree);
        
        // Verify all nodes are preserved
        expect(flattenedNodes.length).toBe(expectedNodeCount);
        
        // Verify root is included
        expect(flattenedNodes).toContain(rootTree);
        
        // Verify all node IDs are unique
        const nodeIds = flattenedNodes.map(n => n.attackId);
        const uniqueIds = new Set(nodeIds);
        expect(uniqueIds.size).toBe(nodeIds.length);
        
        // Verify all generations are preserved
        flattenedNodes.forEach(node => {
          expect(node.generation).toBeGreaterThanOrEqual(1);
          expect(node.generation).toBeLessThanOrEqual(treeConfig.depth);
        });
      }
    ), { numRuns: 50 });
  });
});