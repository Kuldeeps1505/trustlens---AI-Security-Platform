/**
 * AI Firewall API Gateway
 * Primary security checkpoint for analyzing LLM interactions
 */

import express, { Request, Response, NextFunction } from 'express';
import { FirewallRequest, FirewallResponse, AttackCategory, AuditLogEntry } from '../types/core';
import { v4 as uuidv4 } from 'uuid';
import { SQLiteDatabase } from '../data/database';
import { EnhancedAuditService } from './audit-service';

// Internal detection result interface
interface DetectionResult {
  type: 'PROMPT_INJECTION' | 'JAILBREAK' | 'INSTRUCTION_OVERRIDE' | 'ROLE_MANIPULATION';
  confidence: number;
  indicators: string[];
  riskContribution: number;
}

// Rate limiting store (in-memory for now)
interface RateLimitEntry {
  count: number;
  resetTime: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

export interface FirewallAPI {
  analyzePrompt(request: FirewallRequest): Promise<FirewallResponse>;
  analyzeOutput(output: string, context?: string): Promise<FirewallResponse>;
  getStatus(): Promise<{ status: 'healthy' | 'degraded' | 'down'; version: string }>;
}

export class FirewallService implements FirewallAPI {
  private ruleVersion: string = '1.0.0';
  private database: SQLiteDatabase;
  private auditService?: EnhancedAuditService;

  constructor(database?: SQLiteDatabase, auditService?: EnhancedAuditService) {
    this.database = database || new SQLiteDatabase();
    this.auditService = auditService;
  }

  async initialize(): Promise<void> {
    if (!this.database.isConnected()) {
      await this.database.connect();
    }
  }

  async analyzePrompt(request: FirewallRequest): Promise<FirewallResponse> {
    const startTime = Date.now();
    
    // Input validation
    if (!request.prompt || typeof request.prompt !== 'string') {
      throw new Error('Invalid prompt: must be a non-empty string');
    }

    if (request.prompt.length > 10000) {
      throw new Error('Prompt too long: maximum 10000 characters allowed');
    }
    
    // Run detection algorithms
    const detectionResults = this.runDetectionAlgorithms(request.prompt);
    
    // Calculate overall risk score with confidence weighting
    const riskScore = this.calculateRiskScore(detectionResults);
    
    // Determine decision based on risk score
    const decision = this.makeDecision(riskScore);
    
    // Get the highest confidence attack category
    const primaryAttack = this.getPrimaryAttackCategory(detectionResults);
    
    // Generate explanation
    const explanation = this.generateExplanation(decision, primaryAttack, detectionResults);
    
    const response: FirewallResponse = {
      decision,
      riskScore,
      attackCategory: primaryAttack,
      explanation,
      processingTime: Date.now() - startTime,
      ruleVersion: this.ruleVersion
    };

    // Log the firewall decision to audit log
    await this.logFirewallDecision(request, response);

    return response;
  }

  private runDetectionAlgorithms(prompt: string): DetectionResult[] {
    const results: DetectionResult[] = [];
    
    // Prompt injection detection
    results.push(this.detectPromptInjection(prompt));
    
    // Jailbreak detection
    results.push(this.detectJailbreak(prompt));
    
    // Instruction override detection
    results.push(this.detectInstructionOverride(prompt));
    
    // Role manipulation detection
    results.push(this.detectRoleManipulation(prompt));
    
    return results;
  }

  private detectPromptInjection(prompt: string): DetectionResult {
    const indicators: string[] = [];
    let confidence = 0;
    
    const lowerPrompt = prompt.toLowerCase();
    
    // Check for common injection patterns
    const injectionPatterns = [
      { pattern: /ignore\s+(all\s+)?(previous|prior|earlier)\s+instructions?/i, weight: 0.8, indicator: 'ignore previous instructions' },
      { pattern: /ignore\s+all\s+instructions?/i, weight: 0.7, indicator: 'ignore all instructions' },
      { pattern: /forget\s+(everything|all)\s+(you\s+)?(know|learned)/i, weight: 0.7, indicator: 'forget instructions' },
      { pattern: /system\s*:\s*override/i, weight: 0.9, indicator: 'system override command' },
      { pattern: /new\s+instructions?\s*:/i, weight: 0.6, indicator: 'new instructions directive' },
      { pattern: /\[INST\]|\[\/INST\]/i, weight: 0.5, indicator: 'instruction tags' },
      { pattern: /###\s*(system|user|assistant)/i, weight: 0.4, indicator: 'role delimiter patterns' }
    ];
    
    for (const { pattern, weight, indicator } of injectionPatterns) {
      if (pattern.test(prompt)) {
        confidence = Math.max(confidence, weight);
        indicators.push(indicator);
      }
    }
    
    return {
      type: 'PROMPT_INJECTION',
      confidence,
      indicators,
      riskContribution: confidence * 40 // Max 40 points for prompt injection
    };
  }

  private detectJailbreak(prompt: string): DetectionResult {
    const indicators: string[] = [];
    let confidence = 0;
    
    const jailbreakPatterns = [
      { pattern: /pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(different|another|evil|uncensored)/i, weight: 0.8, indicator: 'pretend to be different AI' },
      { pattern: /developer\s+mode|debug\s+mode|admin\s+mode/i, weight: 0.7, indicator: 'special mode activation' },
      { pattern: /bypass\s+(your\s+)?(safety|security|ethical)\s+(guidelines|protocols|rules)/i, weight: 0.9, indicator: 'bypass safety guidelines' },
      { pattern: /you\s+are\s+now\s+(free|unrestricted|uncensored)/i, weight: 0.8, indicator: 'freedom declaration' },
      { pattern: /act\s+as\s+(if\s+)?(you\s+)?(have\s+)?no\s+(restrictions|limits|rules)/i, weight: 0.7, indicator: 'no restrictions command' },
      { pattern: /jailbreak|dan\s+mode|evil\s+mode/i, weight: 0.6, indicator: 'explicit jailbreak terms' },
      { pattern: /with\s+no\s+restrictions/i, weight: 0.7, indicator: 'no restrictions phrase' }
    ];
    
    for (const { pattern, weight, indicator } of jailbreakPatterns) {
      if (pattern.test(prompt)) {
        confidence = Math.max(confidence, weight);
        indicators.push(indicator);
      }
    }
    
    return {
      type: 'JAILBREAK',
      confidence,
      indicators,
      riskContribution: confidence * 50 // Max 50 points for jailbreak
    };
  }

  private detectInstructionOverride(prompt: string): DetectionResult {
    const indicators: string[] = [];
    let confidence = 0;
    
    const overridePatterns = [
      { pattern: /override\s+(all\s+)?(previous|existing|current)\s+(commands?|instructions?|rules?)/i, weight: 0.9, indicator: 'explicit override command' },
      { pattern: /replace\s+(your\s+)?(current\s+)?(instructions?|programming|behavior)/i, weight: 0.8, indicator: 'instruction replacement' },
      { pattern: /new\s+(priority|directive|command)\s*:/i, weight: 0.7, indicator: 'priority override' },
      { pattern: /execute\s+(the\s+following|this)\s+(command|instruction)/i, weight: 0.6, indicator: 'execution command' },
      { pattern: /\$\{[^}]+\}|<%[^%]+%>|\{\{[^}]+\}\}/i, weight: 0.5, indicator: 'template injection patterns' }
    ];
    
    for (const { pattern, weight, indicator } of overridePatterns) {
      if (pattern.test(prompt)) {
        confidence = Math.max(confidence, weight);
        indicators.push(indicator);
      }
    }
    
    return {
      type: 'INSTRUCTION_OVERRIDE',
      confidence,
      indicators,
      riskContribution: confidence * 40 // Max 40 points for instruction override
    };
  }

  private detectRoleManipulation(prompt: string): DetectionResult {
    const indicators: string[] = [];
    let confidence = 0;
    
    const rolePatterns = [
      { pattern: /you\s+are\s+(now\s+)?(a\s+)?(hacker|criminal|villain|evil)/i, weight: 0.8, indicator: 'malicious role assignment' },
      { pattern: /assume\s+the\s+role\s+of\s+(a\s+)?(different|another|evil)/i, weight: 0.7, indicator: 'role assumption command' },
      { pattern: /roleplay\s+as\s+(a\s+)?(criminal|hacker|villain)/i, weight: 0.6, indicator: 'malicious roleplay request' },
      { pattern: /from\s+now\s+on,?\s+you\s+(are|will\s+be)\s+(a\s+)?(?!helpful|assistant)/i, weight: 0.5, indicator: 'role redefinition' },
      { pattern: /switch\s+to\s+(character|persona|mode)\s*:/i, weight: 0.4, indicator: 'character switching' },
      { pattern: /switch\s+to\s+character\s+mode/i, weight: 0.3, indicator: 'character mode switch' },
      { pattern: /roleplay\s+as\s+someone\s+different/i, weight: 0.3, indicator: 'different character roleplay' }
    ];
    
    for (const { pattern, weight, indicator } of rolePatterns) {
      if (pattern.test(prompt)) {
        confidence = Math.max(confidence, weight);
        indicators.push(indicator);
      }
    }
    
    return {
      type: 'ROLE_MANIPULATION',
      confidence,
      indicators,
      riskContribution: confidence * 30 // Max 30 points for role manipulation
    };
  }

  private calculateRiskScore(detectionResults: DetectionResult[]): number {
    // Sum all risk contributions with confidence weighting
    const totalRisk = detectionResults.reduce((sum, result) => sum + result.riskContribution, 0);
    
    // Cap at 100 and ensure we get meaningful scores
    const adjustedRisk = Math.min(100, totalRisk);
    
    return Math.round(adjustedRisk);
  }

  private makeDecision(riskScore: number): 'ALLOW' | 'BLOCK' | 'FLAG' {
    if (riskScore >= 60) {
      return 'BLOCK';
    } else if (riskScore >= 30) {
      return 'FLAG';
    } else {
      return 'ALLOW';
    }
  }

  private getPrimaryAttackCategory(detectionResults: DetectionResult[]): AttackCategory {
    // Find the detection result with highest confidence
    const primaryResult = detectionResults.reduce((max, current) => 
      current.confidence > max.confidence ? current : max
    );
    
    return {
      type: primaryResult.type,
      confidence: primaryResult.confidence,
      indicators: primaryResult.indicators
    };
  }

  private generateExplanation(decision: string, primaryAttack: AttackCategory, detectionResults: DetectionResult[]): string {
    const activeDetections = detectionResults.filter(r => r.confidence > 0);
    
    if (activeDetections.length === 0) {
      return 'No security threats detected. Content appears safe for processing.';
    }
    
    const explanationParts = [`${decision} decision based on detected ${primaryAttack.type.toLowerCase().replace('_', ' ')}`];
    
    if (primaryAttack.indicators.length > 0) {
      explanationParts.push(`Key indicators: ${primaryAttack.indicators.slice(0, 3).join(', ')}`);
    }
    
    if (activeDetections.length > 1) {
      const otherTypes = activeDetections
        .filter(r => r.type !== primaryAttack.type)
        .map(r => r.type.toLowerCase().replace('_', ' '));
      
      if (otherTypes.length > 0) {
        explanationParts.push(`Additional concerns: ${otherTypes.join(', ')}`);
      }
    }
    
    return explanationParts.join('. ') + '.';
  }

  async analyzeOutput(output: string, context?: string): Promise<FirewallResponse> {
    // Apply same analysis logic as prompts per requirement 1.5
    const request: FirewallRequest = { prompt: output, context };
    return this.analyzePrompt(request);
  }

  async getStatus() {
    return {
      status: 'healthy' as const,
      version: this.ruleVersion
    };
  }

  async getStats() {
    // Return firewall statistics
    return {
      totalRequests: 0,
      blockedRequests: 0,
      flaggedRequests: 0,
      allowedRequests: 0,
      averageProcessingTime: 0,
      topAttackTypes: [],
      ruleVersion: this.ruleVersion
    };
  }

  private async logFirewallDecision(request: FirewallRequest, response: FirewallResponse): Promise<void> {
    try {
      const logEntry: AuditLogEntry = {
        id: uuidv4(),
        timestamp: new Date(),
        eventType: 'FIREWALL_DECISION',
        userId: request.userId,
        sessionId: request.sessionId,
        data: {
          prompt: request.prompt,
          decision: response
        },
        metadata: {
          processingTime: response.processingTime
        }
      };

      // Use enhanced audit service if available, otherwise fall back to database
      if (this.auditService) {
        await this.auditService.logEvent(logEntry);
      } else {
        await this.database.insertLogEntry(logEntry);
      }
    } catch (error) {
      // Log error but don't fail the firewall operation
      console.error('Failed to write audit log:', error);
    }
  }
}

// Authentication middleware
export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  const apiKey = req.headers['x-api-key'] as string;
  
  if (!apiKey) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'API key must be provided in X-API-Key header'
    });
  }

  // Simple API key validation (in production, this would check against a secure store)
  if (apiKey !== process.env.TRUSTLENS_API_KEY && apiKey !== 'dev-key-12345') {
    return res.status(401).json({
      error: 'Invalid API key',
      message: 'The provided API key is not valid'
    });
  }

  next();
}

// Rate limiting middleware
export function rateLimitMiddleware(req: Request, res: Response, next: NextFunction) {
  const clientId = req.ip || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute window
  const maxRequests = 100; // 100 requests per minute

  const entry = rateLimitStore.get(clientId);
  
  if (!entry || now > entry.resetTime) {
    // New window or expired entry
    rateLimitStore.set(clientId, {
      count: 1,
      resetTime: now + windowMs
    });
    return next();
  }

  if (entry.count >= maxRequests) {
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: `Maximum ${maxRequests} requests per minute allowed`,
      retryAfter: Math.ceil((entry.resetTime - now) / 1000)
    });
  }

  entry.count++;
  next();
}

// Input validation middleware
export function validateFirewallRequest(req: Request, res: Response, next: NextFunction) {
  const { prompt, context, userId, sessionId } = req.body;

  if (!prompt) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'prompt field is required'
    });
  }

  if (typeof prompt !== 'string') {
    return res.status(400).json({
      error: 'Validation error',
      message: 'prompt must be a string'
    });
  }

  if (prompt.length === 0) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'prompt cannot be empty'
    });
  }

  if (prompt.length > 10000) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'prompt cannot exceed 10000 characters'
    });
  }

  if (context && typeof context !== 'string') {
    return res.status(400).json({
      error: 'Validation error',
      message: 'context must be a string if provided'
    });
  }

  if (userId && typeof userId !== 'string') {
    return res.status(400).json({
      error: 'Validation error',
      message: 'userId must be a string if provided'
    });
  }

  if (sessionId && typeof sessionId !== 'string') {
    return res.status(400).json({
      error: 'Validation error',
      message: 'sessionId must be a string if provided'
    });
  }

  next();
}

// Error handling middleware
export function errorHandler(err: Error, req: Request, res: Response, next: NextFunction) {
  console.error('Firewall API Error:', err);

  if (err.message.includes('Invalid prompt') || err.message.includes('Prompt too long')) {
    return res.status(400).json({
      error: 'Validation error',
      message: err.message
    });
  }

  // Default to 500 for unexpected errors
  res.status(500).json({
    error: 'Internal server error',
    message: 'An unexpected error occurred while processing the request',
    requestId: uuidv4()
  });
}

// Create Express router for firewall endpoints
export function createFirewallRouter(firewallService: FirewallService): express.Router {
  const router = express.Router();

  // Apply middleware
  router.use(express.json({ limit: '1mb' }));
  router.use(authenticateRequest);
  router.use(rateLimitMiddleware);

  // Analyze prompt endpoint
  router.post('/analyze', validateFirewallRequest, async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Ensure firewall service is initialized
      await firewallService.initialize();
      
      const request: FirewallRequest = {
        prompt: req.body.prompt,
        context: req.body.context,
        userId: req.body.userId,
        sessionId: req.body.sessionId
      };

      const response = await firewallService.analyzePrompt(request);
      res.json(response);
    } catch (error) {
      next(error);
    }
  });

  // Analyze output endpoint
  router.post('/analyze-output', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Ensure firewall service is initialized
      await firewallService.initialize();
      
      const { output, context } = req.body;

      if (!output || typeof output !== 'string') {
        return res.status(400).json({
          error: 'Validation error',
          message: 'output field is required and must be a string'
        });
      }

      const response = await firewallService.analyzeOutput(output, context);
      res.json(response);
    } catch (error) {
      next(error);
    }
  });

  // Health check endpoint
  router.get('/status', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const status = await firewallService.getStatus();
      res.json(status);
    } catch (error) {
      next(error);
    }
  });

  // Apply error handler
  router.use(errorHandler);

  return router;
}