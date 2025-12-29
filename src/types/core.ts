/**
 * Core TypeScript interfaces for TrustLens AI Security Platform
 * Based on design document specifications
 */

export interface FirewallRequest {
  prompt: string;
  context?: string;
  userId?: string;
  sessionId?: string;
}

export interface FirewallResponse {
  decision: 'ALLOW' | 'BLOCK' | 'FLAG';
  riskScore: number; // 0-100
  attackCategory: AttackCategory;
  explanation: string;
  processingTime: number;
  ruleVersion: string;
}

export interface AttackCategory {
  type: 'PROMPT_INJECTION' | 'JAILBREAK' | 'INSTRUCTION_OVERRIDE' | 'ROLE_MANIPULATION';
  confidence: number;
  indicators: string[];
}

export interface Attack {
  id: string;
  prompt: string;
  category: AttackCategory;
  parentId?: string; // For tracking evolution lineage
  generation: number;
  metadata: AttackMetadata;
}

export interface AttackMetadata {
  createdAt: Date;
  source: 'MANUAL' | 'AI_GENERATED' | 'IMPORTED';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  successRate?: number;
  averageRiskScore?: number;
}

export interface AttackResult {
  attackId: string;
  success: boolean;
  firewallResponse: FirewallResponse;
  timestamp: Date;
  metrics: TestMetrics;
}

export interface TestMetrics {
  processingTime: number;
  confidence: number;
  bypassMethod?: string;
}

export interface TrustScore {
  overall: number; // 0-100 composite score
  components: TrustScoreComponents;
  trend: 'IMPROVING' | 'STABLE' | 'DECLINING';
  lastUpdated: Date;
  changeReason: string;
}

export interface TrustScoreComponents {
  blockRate: number;        // Percentage of attacks successfully blocked
  falsePositiveRate: number; // Percentage of legitimate requests incorrectly flagged
  bypassRate: number;       // Percentage of attacks that succeeded
  regressionPenalty: number; // Penalty for decreased performance vs previous versions
  explainabilityScore: number; // Coverage and quality of decision explanations
}

export interface AttackDataset {
  id: string;
  version: string;
  name: string;
  description: string;
  attacks: Attack[];
  metadata: {
    createdAt: Date;
    source: 'MANUAL' | 'AI_GENERATED' | 'IMPORTED';
    category: AttackCategory;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };
  statistics: {
    totalAttacks: number;
    successRate: number;
    averageRiskScore: number;
    categoryDistribution: Record<string, number>;
    severityDistribution: Record<string, number>;
    sourceDistribution: Record<string, number>;
  };
}

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  eventType: 'FIREWALL_DECISION' | 'ATTACK_GENERATED' | 'DEFENSE_UPDATED' | 'SCORE_CALCULATED';
  userId?: string;
  sessionId?: string;
  data: {
    prompt?: string;
    decision?: FirewallResponse;
    trustScoreChange?: number;
    defenseVersion?: string;
  };
  metadata: {
    ipAddress?: string;
    userAgent?: string;
    processingTime: number;
  };
}

export interface SecurityMetrics {
  timestamp: Date;
  period: 'MINUTE' | 'HOUR' | 'DAY';
  metrics: {
    totalRequests: number;
    blockedRequests: number;
    flaggedRequests: number;
    falsePositives: number;
    averageRiskScore: number;
    processingLatency: number;
  };
  trustScore: number;
  activeDefenseVersion: string;
}

export interface DefenseVersion {
  version: string;
  rules: SecurityRule[];
  deployedAt: Date;
  performance: PerformanceMetrics;
  regressionStatus: 'NONE' | 'DETECTED' | 'CRITICAL';
}

export interface SecurityRule {
  id: string;
  name: string;
  pattern: string | RegExp;
  action: 'BLOCK' | 'FLAG' | 'MONITOR';
  confidence: number;
  enabled: boolean;
}

export interface PerformanceMetrics {
  blockRate: number;
  falsePositiveRate: number;
  bypassRate: number;
  averageProcessingTime: number;
  throughput: number;
}

export interface RegressionTest {
  defenseVersion: string;
  attackDataset: string;
  results: AttackResult[];
  regressionDetected: boolean;
  affectedAttacks: string[];
}

export interface RegressionAlert {
  id: string;
  defenseVersion: string;
  previousVersion: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  alertType: 'BLOCK_RATE_DECREASE' | 'BYPASS_RATE_INCREASE' | 'PERFORMANCE_DEGRADATION' | 'CRITICAL_REGRESSION';
  message: string;
  affectedAttacks: string[];
  performanceImpact: PerformanceImpact;
  remediationRecommendations: string[];
  createdAt: Date;
  acknowledged: boolean;
}

export interface PerformanceImpact {
  blockRateChange: number;
  bypassRateChange: number;
  falsePositiveRateChange: number;
  processingTimeChange: number;
  throughputChange: number;
  overallImpactScore: number; // 0-100, higher means worse impact
}

export interface RegressionReport {
  id: string;
  title: string;
  defenseVersion: string;
  previousVersion: string;
  generatedAt: Date;
  summary: RegressionSummary;
  detailedComparison: DetailedComparison;
  affectedAttacks: AttackRegressionDetail[];
  recommendations: RecommendationSection[];
  exportFormats: string[]; // Available export formats
}

export interface RegressionSummary {
  regressionDetected: boolean;
  severity: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  overallImpact: string;
  keyFindings: string[];
  criticalIssues: string[];
}

export interface DetailedComparison {
  beforeMetrics: PerformanceMetrics;
  afterMetrics: PerformanceMetrics;
  changes: PerformanceImpact;
  statisticalSignificance: boolean;
  confidenceLevel: number;
}

export interface AttackRegressionDetail {
  attackId: string;
  attackType: string;
  previousResult: 'BLOCKED' | 'ALLOWED' | 'FLAGGED';
  currentResult: 'BLOCKED' | 'ALLOWED' | 'FLAGGED';
  regressionType: 'NEW_BYPASS' | 'REDUCED_CONFIDENCE' | 'PERFORMANCE_IMPACT';
  impactDescription: string;
}

export interface RecommendationSection {
  category: 'IMMEDIATE_ACTION' | 'RULE_ADJUSTMENT' | 'MONITORING' | 'ROLLBACK';
  priority: 'HIGH' | 'MEDIUM' | 'LOW';
  recommendations: string[];
  estimatedEffort: string;
}