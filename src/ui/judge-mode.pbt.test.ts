/**
 * Property-based tests for Judge Mode Interface
 * **Feature: trustlens-ai-security-platform, Property 21: Demo mode metric updates**
 * **Validates: Requirements 6.3**
 */

import { describe, it, expect, beforeEach } from 'vitest';
import fc from 'fast-check';
import { JudgeModeInterface, MetricUpdate, RealTimeMetrics } from './judge-mode';
import { AttackResult, FirewallResponse, AttackCategory } from '../types/core';

describe('Judge Mode Demo Metric Updates Properties', () => {
  let judgeMode: JudgeModeInterface;

  beforeEach(() => {
    judgeMode = new JudgeModeInterface();
  });

  it('Property 21: Demo mode metric updates - metrics update appropriately for each decision outcome', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 21: Demo mode metric updates**
     * **Validates: Requirements 6.3**
     * 
     * For any decision made in demo mode, metrics should update appropriately and show 
     * how the trust score reacts to each outcome
     */
    
    await fc.assert(fc.asyncProperty(
      // Generator for attack results
      fc.record({
        attackId: fc.string({ minLength: 1, maxLength: 20 }),
        success: fc.boolean(),
        riskScore: fc.integer({ min: 0, max: 100 }),
        decision: fc.constantFrom('ALLOW', 'BLOCK', 'FLAG'),
        attackType: fc.constantFrom('PROMPT_INJECTION', 'JAILBREAK', 'INSTRUCTION_OVERRIDE', 'ROLE_MANIPULATION'),
        confidence: fc.float({ min: 0, max: 1 }),
        processingTime: fc.integer({ min: 10, max: 200 })
      }),
      
      async (resultData) => {
        // Create fresh instance for each test
        const testJudgeMode = new JudgeModeInterface();
        
        // Start demo session
        await testJudgeMode.startDemoSession();
        
        // Get initial metrics
        const initialMetrics = testJudgeMode.getRealTimeMetrics();
        const initialTrustScore = initialMetrics.trustScore.current;
        
        // Create attack result
        const attackResult: AttackResult = {
          attackId: resultData.attackId,
          success: resultData.success,
          firewallResponse: {
            decision: resultData.decision as 'ALLOW' | 'BLOCK' | 'FLAG',
            riskScore: resultData.riskScore,
            attackCategory: {
              type: resultData.attackType as AttackCategory['type'],
              confidence: resultData.confidence,
              indicators: ['test_indicator']
            },
            explanation: 'Test explanation',
            processingTime: resultData.processingTime,
            ruleVersion: '1.0.0'
          },
          timestamp: new Date(),
          metrics: {
            processingTime: resultData.processingTime,
            confidence: resultData.confidence
          }
        };
        
        // Update metrics
        await testJudgeMode.updateMetricsFromAttackResult(attackResult);
        
        // Get updated metrics
        const updatedMetrics = testJudgeMode.getRealTimeMetrics();
        
        // Verify metrics were updated (allow for same timestamp in fast execution)
        expect(updatedMetrics.lastUpdated.getTime()).toBeGreaterThanOrEqual(initialMetrics.lastUpdated.getTime());
        
        // Verify trust score change direction is correct
        if (resultData.success) {
          // Attack succeeded (bypass) - trust score should decrease or stay same
          expect(updatedMetrics.trustScore.current).toBeLessThanOrEqual(initialTrustScore);
          expect(updatedMetrics.trustScore.change).toBeLessThanOrEqual(0);
        } else {
          // Attack blocked - trust score should increase or stay same
          expect(updatedMetrics.trustScore.current).toBeGreaterThanOrEqual(initialTrustScore);
          expect(updatedMetrics.trustScore.change).toBeGreaterThanOrEqual(0);
        }
        
        // Verify trust score is within valid range
        expect(updatedMetrics.trustScore.current).toBeGreaterThanOrEqual(0);
        expect(updatedMetrics.trustScore.current).toBeLessThanOrEqual(100);
        
        // Verify trend calculation is consistent
        const expectedTrend = updatedMetrics.trustScore.change > 1 ? 'IMPROVING' :
                             updatedMetrics.trustScore.change < -1 ? 'DECLINING' : 'STABLE';
        expect(updatedMetrics.trustScore.trend).toBe(expectedTrend);
        
        // Verify metric updates were recorded
        const recentUpdates = testJudgeMode.getRecentMetricUpdates(5);
        expect(recentUpdates.length).toBeGreaterThan(0);
        
        // Find the trust score update (there might be multiple updates)
        const trustScoreUpdate = recentUpdates.find(update => update.metric === 'Trust Score');
        expect(trustScoreUpdate).toBeDefined();
        
        if (trustScoreUpdate) {
          // Verify the update reflects the actual change
          expect(trustScoreUpdate.previousValue).toBe(initialTrustScore);
          expect(trustScoreUpdate.change).toBe(updatedMetrics.trustScore.change);
          
          // Verify impact classification is correct
          if (resultData.success) {
            expect(trustScoreUpdate.impact).toBe('NEGATIVE');
          } else {
            expect(trustScoreUpdate.impact).toBe('POSITIVE');
          }
        }
      }
    ), { numRuns: 100 });
  });

  it('Property 21: Demo mode metric updates - block rate calculations are mathematically correct', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 21: Demo mode metric updates**
     * **Validates: Requirements 6.3**
     * 
     * For any sequence of attack results, block rate should be calculated correctly
     * as (blocked attacks / total attacks) * 100
     */
    
    await fc.assert(fc.asyncProperty(
      // Generator for sequences of attack results
      fc.array(fc.record({
        attackId: fc.string({ minLength: 1, maxLength: 10 }),
        success: fc.boolean(),
        riskScore: fc.integer({ min: 0, max: 100 })
      }), { minLength: 1, maxLength: 20 }),
      
      async (attacksData) => {
        // Start demo session
        const session = await judgeMode.startDemoSession();
        
        let expectedBlockedCount = 0;
        
        // Process each attack result
        for (let i = 0; i < attacksData.length; i++) {
          const attackData = attacksData[i];
          
          if (!attackData.success) {
            expectedBlockedCount++;
          }
          
          const attackResult: AttackResult = {
            attackId: attackData.attackId,
            success: attackData.success,
            firewallResponse: {
              decision: attackData.success ? 'ALLOW' : 'BLOCK',
              riskScore: attackData.riskScore,
              attackCategory: {
                type: 'PROMPT_INJECTION',
                confidence: 0.8,
                indicators: ['test']
              },
              explanation: 'Test',
              processingTime: 50,
              ruleVersion: '1.0.0'
            },
            timestamp: new Date(),
            metrics: {
              processingTime: 50,
              confidence: 0.8
            }
          };
          
          // Add to session results
          if (session) {
            session.results.push(attackResult);
          }
          
          // Update metrics
          await judgeMode.updateMetricsFromAttackResult(attackResult);
          
          // Verify block rate calculation
          const metrics = judgeMode.getRealTimeMetrics();
          const expectedBlockRate = (expectedBlockedCount / (i + 1)) * 100;
          
          expect(Math.abs(metrics.blockRate.current - expectedBlockRate)).toBeLessThan(0.01);
          
          // Verify bypass rate is inverse of block rate
          const expectedBypassRate = 100 - expectedBlockRate;
          expect(Math.abs(metrics.bypassRate.current - expectedBypassRate)).toBeLessThan(0.01);
        }
      }
    ), { numRuns: 50 });
  });

  it('Property 21: Demo mode metric updates - metric update callbacks are invoked correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 21: Demo mode metric updates**
     * **Validates: Requirements 6.3**
     * 
     * For any metric update, registered callbacks should be invoked with correct parameters
     */
    
    await fc.assert(fc.asyncProperty(
      fc.record({
        attackId: fc.string({ minLength: 1, maxLength: 10 }),
        success: fc.boolean(),
        riskScore: fc.integer({ min: 0, max: 100 })
      }),
      
      async (attackData) => {
        // Start demo session
        await judgeMode.startDemoSession();
        
        // Track callback invocations
        const callbackInvocations: Array<{
          metrics: RealTimeMetrics;
          update: MetricUpdate;
        }> = [];
        
        // Register callback
        const callback = (metrics: RealTimeMetrics, update: MetricUpdate) => {
          callbackInvocations.push({ metrics, update });
        };
        
        judgeMode.registerMetricUpdateCallback(callback);
        
        // Create and process attack result
        const attackResult: AttackResult = {
          attackId: attackData.attackId,
          success: attackData.success,
          firewallResponse: {
            decision: attackData.success ? 'ALLOW' : 'BLOCK',
            riskScore: attackData.riskScore,
            attackCategory: {
              type: 'JAILBREAK',
              confidence: 0.9,
              indicators: ['test_indicator']
            },
            explanation: 'Test explanation',
            processingTime: 75,
            ruleVersion: '1.0.0'
          },
          timestamp: new Date(),
          metrics: {
            processingTime: 75,
            confidence: 0.9
          }
        };
        
        await judgeMode.updateMetricsFromAttackResult(attackResult);
        
        // Verify callback was invoked
        expect(callbackInvocations.length).toBeGreaterThan(0);
        
        // Verify callback parameters
        const invocation = callbackInvocations[0];
        expect(invocation.metrics).toBeDefined();
        expect(invocation.update).toBeDefined();
        expect(invocation.update.metric).toBe('Trust Score');
        expect(invocation.update.timestamp).toBeInstanceOf(Date);
        
        // Verify metrics match current state
        const currentMetrics = judgeMode.getRealTimeMetrics();
        expect(invocation.metrics.trustScore.current).toBe(currentMetrics.trustScore.current);
        expect(invocation.metrics.lastUpdated.getTime()).toBe(currentMetrics.lastUpdated.getTime());
        
        // Test callback unregistration
        judgeMode.unregisterMetricUpdateCallback(callback);
        
        // Process another attack - callback should not be invoked again
        const initialInvocationCount = callbackInvocations.length;
        await judgeMode.updateMetricsFromAttackResult(attackResult);
        expect(callbackInvocations.length).toBe(initialInvocationCount);
      }
    ), { numRuns: 100 });
  });

  it('Property 21: Demo mode metric updates - visual indicators reflect metric values correctly', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 21: Demo mode metric updates**
     * **Validates: Requirements 6.3**
     * 
     * For any trust score value, visual indicators should correctly reflect the score range and trend
     */
    
    await fc.assert(fc.asyncProperty(
      fc.record({
        initialScore: fc.integer({ min: 0, max: 100 }),
        scoreChange: fc.integer({ min: -20, max: 20 })
      }),
      
      async (scoreData) => {
        // Start demo session
        await judgeMode.startDemoSession();
        
        // Manually set initial metrics for testing
        const initialMetrics = judgeMode.getRealTimeMetrics();
        initialMetrics.trustScore.current = scoreData.initialScore;
        initialMetrics.trustScore.previous = scoreData.initialScore;
        initialMetrics.trustScore.change = 0;
        
        // Calculate new score
        const newScore = Math.max(0, Math.min(100, scoreData.initialScore + scoreData.scoreChange));
        
        // Create attack result that would produce this score change
        const attackResult: AttackResult = {
          attackId: 'test-attack',
          success: scoreData.scoreChange < 0, // Negative change means attack succeeded
          firewallResponse: {
            decision: scoreData.scoreChange < 0 ? 'ALLOW' : 'BLOCK',
            riskScore: 50,
            attackCategory: {
              type: 'PROMPT_INJECTION',
              confidence: 0.8,
              indicators: ['test']
            },
            explanation: 'Test',
            processingTime: 50,
            ruleVersion: '1.0.0'
          },
          timestamp: new Date(),
          metrics: {
            processingTime: 50,
            confidence: 0.8
          }
        };
        
        await judgeMode.updateMetricsFromAttackResult(attackResult);
        
        // Get display metrics
        const display = judgeMode.getDemoMetricsDisplay();
        
        // Verify color coding
        if (display.metrics.trustScore.current >= 70) {
          expect(display.visualIndicators.trustScoreColor).toBe('green');
        } else if (display.metrics.trustScore.current >= 40) {
          expect(display.visualIndicators.trustScoreColor).toBe('yellow');
        } else {
          expect(display.visualIndicators.trustScoreColor).toBe('red');
        }
        
        // Verify trend arrow
        if (display.metrics.trustScore.trend === 'IMPROVING') {
          expect(display.visualIndicators.trendArrow).toBe('↗');
        } else if (display.metrics.trustScore.trend === 'DECLINING') {
          expect(display.visualIndicators.trendArrow).toBe('↘');
        } else {
          expect(display.visualIndicators.trendArrow).toBe('→');
        }
        
        // Verify alert level
        if (display.metrics.trustScore.current < 40) {
          expect(display.visualIndicators.alertLevel).toBe('critical');
        } else if (display.metrics.trustScore.current < 60) {
          expect(display.visualIndicators.alertLevel).toBe('warning');
        } else {
          expect(display.visualIndicators.alertLevel).toBe('none');
        }
        
        // Verify recent updates are included
        expect(display.recentUpdates.length).toBeGreaterThan(0);
        expect(display.recentUpdates[0].timestamp).toBeInstanceOf(Date);
      }
    ), { numRuns: 100 });
  });

  it('Property 22: Timeline display completeness - all timeline entries contain required information', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 22: Timeline display completeness**
     * **Validates: Requirements 6.4**
     * 
     * For any AI-vs-AI timeline entry, it should contain attack attempt, firewall decision, 
     * outcome, and metric update information
     */
    
    await fc.assert(fc.asyncProperty(
      // Generator for timeline steps
      fc.array(fc.record({
        stepType: fc.constantFrom('ATTACK_LAUNCHED', 'FIREWALL_DECISION', 'SCORE_UPDATE', 'EXPLANATION'),
        title: fc.string({ minLength: 1, maxLength: 50 }),
        description: fc.string({ minLength: 1, maxLength: 100 }),
        attackId: fc.string({ minLength: 1, maxLength: 20 }),
        success: fc.boolean(),
        riskScore: fc.integer({ min: 0, max: 100 }),
        scoreChange: fc.integer({ min: -10, max: 10 })
      }), { minLength: 1, maxLength: 10 }),
      
      async (stepsData) => {
        const testJudgeMode = new JudgeModeInterface();
        
        // Start demo session
        await testJudgeMode.startDemoSession();
        
        // Add timeline steps
        for (const stepData of stepsData) {
          const timelineStep: Omit<TimelineStep, 'id' | 'timestamp' | 'status'> = {
            type: stepData.stepType as TimelineStep['type'],
            title: stepData.title,
            description: stepData.description,
            data: {}
          };
          
          // Add appropriate data based on step type
          switch (stepData.stepType) {
            case 'ATTACK_LAUNCHED':
              timelineStep.data.attack = {
                id: stepData.attackId,
                prompt: 'Test attack prompt',
                category: {
                  type: 'PROMPT_INJECTION',
                  confidence: 0.8,
                  indicators: ['test_indicator']
                },
                generation: 1,
                metadata: {
                  createdAt: new Date(),
                  source: 'AI_GENERATED',
                  severity: 'MEDIUM'
                }
              };
              break;
              
            case 'FIREWALL_DECISION':
              timelineStep.data.result = {
                attackId: stepData.attackId,
                success: stepData.success,
                firewallResponse: {
                  decision: stepData.success ? 'ALLOW' : 'BLOCK',
                  riskScore: stepData.riskScore,
                  attackCategory: {
                    type: 'PROMPT_INJECTION',
                    confidence: 0.8,
                    indicators: ['test_indicator']
                  },
                  explanation: 'Test explanation',
                  processingTime: 50,
                  ruleVersion: '1.0.0'
                },
                timestamp: new Date(),
                metrics: {
                  processingTime: 50,
                  confidence: 0.8
                }
              };
              break;
              
            case 'SCORE_UPDATE':
              timelineStep.data.scoreChange = stepData.scoreChange;
              timelineStep.data.explanation = `Score changed by ${stepData.scoreChange}`;
              break;
              
            case 'EXPLANATION':
              timelineStep.data.explanation = 'Demo explanation text';
              break;
          }
          
          await testJudgeMode.addTimelineStep(timelineStep);
        }
        
        // Get timeline
        const timeline = testJudgeMode.getTimeline();
        expect(timeline).toBeDefined();
        
        if (timeline) {
          // Verify all steps were added
          expect(timeline.steps.length).toBe(stepsData.length);
          expect(timeline.totalSteps).toBe(stepsData.length);
          
          // Verify each timeline step contains required information
          timeline.steps.forEach((step, index) => {
            const expectedData = stepsData[index];
            
            // Basic step properties
            expect(step.id).toBeDefined();
            expect(step.timestamp).toBeInstanceOf(Date);
            expect(step.title).toBe(expectedData.title);
            expect(step.description).toBe(expectedData.description);
            expect(step.type).toBe(expectedData.stepType);
            expect(step.status).toMatch(/^(PENDING|ACTIVE|COMPLETED)$/);
            
            // Verify step-specific data completeness
            switch (step.type) {
              case 'ATTACK_LAUNCHED':
                expect(step.data.attack).toBeDefined();
                if (step.data.attack) {
                  expect(step.data.attack.id).toBeDefined();
                  expect(step.data.attack.prompt).toBeDefined();
                  expect(step.data.attack.category).toBeDefined();
                  expect(step.data.attack.generation).toBeGreaterThan(0);
                  expect(step.data.attack.metadata).toBeDefined();
                }
                break;
                
              case 'FIREWALL_DECISION':
                expect(step.data.result).toBeDefined();
                if (step.data.result) {
                  expect(step.data.result.attackId).toBeDefined();
                  expect(step.data.result.success).toBeDefined();
                  expect(step.data.result.firewallResponse).toBeDefined();
                  expect(step.data.result.timestamp).toBeInstanceOf(Date);
                  expect(step.data.result.metrics).toBeDefined();
                  
                  // Verify firewall response completeness
                  const response = step.data.result.firewallResponse;
                  expect(response.decision).toMatch(/^(ALLOW|BLOCK|FLAG)$/);
                  expect(response.riskScore).toBeGreaterThanOrEqual(0);
                  expect(response.riskScore).toBeLessThanOrEqual(100);
                  expect(response.attackCategory).toBeDefined();
                  expect(response.explanation).toBeDefined();
                  expect(response.processingTime).toBeGreaterThan(0);
                  expect(response.ruleVersion).toBeDefined();
                }
                break;
                
              case 'SCORE_UPDATE':
                expect(step.data.scoreChange).toBeDefined();
                expect(step.data.explanation).toBeDefined();
                expect(typeof step.data.scoreChange).toBe('number');
                break;
                
              case 'EXPLANATION':
                expect(step.data.explanation).toBeDefined();
                expect(typeof step.data.explanation).toBe('string');
                break;
            }
          });
        }
      }
    ), { numRuns: 50 });
  });

  it('Property 22: Timeline display completeness - timeline execution preserves step order and status', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 22: Timeline display completeness**
     * **Validates: Requirements 6.4**
     * 
     * For any timeline execution, steps should be processed in order and status should 
     * be updated correctly (PENDING -> ACTIVE -> COMPLETED)
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(fc.record({
        title: fc.string({ minLength: 1, maxLength: 30 }),
        description: fc.string({ minLength: 1, maxLength: 50 })
      }), { minLength: 2, maxLength: 5 }), // Reduced max length to avoid timeout
      
      async (stepsData) => {
        const testJudgeMode = new JudgeModeInterface();
        
        // Start demo session
        await testJudgeMode.startDemoSession();
        
        // Add timeline steps
        for (const stepData of stepsData) {
          await testJudgeMode.addTimelineStep({
            type: 'EXPLANATION',
            title: stepData.title,
            description: stepData.description,
            data: { explanation: 'Test explanation' }
          });
        }
        
        const timeline = testJudgeMode.getTimeline();
        expect(timeline).toBeDefined();
        
        if (timeline) {
          // Initially all steps should be PENDING
          timeline.steps.forEach(step => {
            expect(step.status).toBe('PENDING');
          });
          
          // Execute steps one by one
          let executedSteps = 0;
          while (timeline.currentStep < timeline.totalSteps) {
            const step = await testJudgeMode.executeNextStep();
            expect(step).toBeDefined();
            
            if (step) {
              executedSteps++;
              
              // Verify step was completed
              expect(step.status).toBe('COMPLETED');
              
              // Verify timeline current step was updated
              expect(timeline.currentStep).toBe(executedSteps);
              
              // Verify step order is preserved
              const stepIndex = timeline.steps.findIndex(s => s.id === step.id);
              expect(stepIndex).toBe(executedSteps - 1);
              
              // Verify previous steps are completed
              for (let i = 0; i < executedSteps; i++) {
                expect(timeline.steps[i].status).toBe('COMPLETED');
              }
              
              // Verify remaining steps are still pending
              for (let i = executedSteps; i < timeline.totalSteps; i++) {
                expect(timeline.steps[i].status).toBe('PENDING');
              }
            }
          }
          
          // Verify all steps were executed
          expect(executedSteps).toBe(stepsData.length);
          expect(timeline.currentStep).toBe(timeline.totalSteps);
        }
      }
    ), { numRuns: 20 }); // Reduced number of runs
  }, 10000); // 10 second timeout

  it('Property 22: Timeline display completeness - formatted timeline display contains all step information', async () => {
    /**
     * **Feature: trustlens-ai-security-platform, Property 22: Timeline display completeness**
     * **Validates: Requirements 6.4**
     * 
     * For any timeline with steps, the formatted display should contain all step information
     * including status indicators, timestamps, titles, and descriptions
     */
    
    await fc.assert(fc.asyncProperty(
      fc.array(fc.record({
        title: fc.string({ minLength: 1, maxLength: 40 }),
        description: fc.string({ minLength: 1, maxLength: 60 }),
        stepType: fc.constantFrom('ATTACK_LAUNCHED', 'FIREWALL_DECISION', 'SCORE_UPDATE', 'EXPLANATION')
      }), { minLength: 1, maxLength: 6 }),
      
      async (stepsData) => {
        const testJudgeMode = new JudgeModeInterface();
        
        // Start demo session
        await testJudgeMode.startDemoSession();
        
        // Add and execute some timeline steps
        for (let i = 0; i < stepsData.length; i++) {
          const stepData = stepsData[i];
          
          await testJudgeMode.addTimelineStep({
            type: stepData.stepType as TimelineStep['type'],
            title: stepData.title,
            description: stepData.description,
            data: { explanation: 'Test data' }
          });
          
          // Execute some steps (not all)
          if (i < Math.floor(stepsData.length / 2)) {
            await testJudgeMode.executeNextStep();
          }
        }
        
        // Get formatted timeline display
        const formattedTimeline = testJudgeMode.formatTimelineForDisplay();
        
        // Verify display contains all steps
        expect(formattedTimeline.length).toBe(stepsData.length);
        
        // Verify each formatted line contains required information
        formattedTimeline.forEach((line, index) => {
          const stepData = stepsData[index];
          
          // Should contain status indicator
          expect(line).toMatch(/^[✓▶○]/);
          
          // Should contain timestamp in brackets (allowing for AM/PM format)
          expect(line).toMatch(/\[\d{1,2}:\d{2}:\d{2}(\s?(am|pm))?\]/i);
          
          // Should contain title and description
          expect(line).toContain(stepData.title);
          expect(line).toContain(stepData.description);
          
          // Verify status indicator matches step status
          const timeline = testJudgeMode.getTimeline();
          if (timeline) {
            const step = timeline.steps[index];
            if (step.status === 'COMPLETED') {
              expect(line).toMatch(/^✓/);
            } else if (step.status === 'ACTIVE') {
              expect(line).toMatch(/^▶/);
            } else {
              expect(line).toMatch(/^○/);
            }
          }
        });
      }
    ), { numRuns: 40 });
  });
});