/**
 * Security Log Explorer
 * Professional SOC-style log filtering, search, and export functionality
 */

import { AuditLogEntry } from '../types/core';

export interface LogFilter {
  startTime?: Date;
  endTime?: Date;
  severity?: ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')[];
  attackType?: ('PROMPT_INJECTION' | 'JAILBREAK' | 'INSTRUCTION_OVERRIDE' | 'ROLE_MANIPULATION')[];
  eventType?: ('FIREWALL_DECISION' | 'ATTACK_GENERATED' | 'DEFENSE_UPDATED' | 'SCORE_CALCULATED')[];
  userId?: string;
  sessionId?: string;
  decision?: ('ALLOW' | 'BLOCK' | 'FLAG')[];
  riskScoreMin?: number;
  riskScoreMax?: number;
}

export interface LogSearchQuery {
  searchTerm: string;
  searchFields: ('prompt' | 'explanation' | 'userId' | 'sessionId')[];
  caseSensitive: boolean;
  useRegex: boolean;
}

export interface LogExportOptions {
  format: 'json' | 'csv' | 'siem';
  includeMetadata: boolean;
  dateFormat: 'iso' | 'unix' | 'human';
  fieldSeparator?: string; // For CSV format
}

export interface LogExplorerResult {
  logs: AuditLogEntry[];
  totalCount: number;
  filteredCount: number;
  pagination: {
    page: number;
    pageSize: number;
    totalPages: number;
  };
  executionTime: number;
}

export interface LogStatistics {
  totalLogs: number;
  eventTypeDistribution: Record<string, number>;
  severityDistribution: Record<string, number>;
  decisionDistribution: Record<string, number>;
  timeRange: {
    earliest: Date;
    latest: Date;
  };
  averageRiskScore: number;
  topUsers: Array<{ userId: string; count: number }>;
}

export class SecurityLogExplorer {
  private logs: AuditLogEntry[] = [];
  private indexedLogs: Map<string, AuditLogEntry[]> = new Map();

  constructor() {
    this.buildSearchIndex();
  }

  async loadLogs(logs: AuditLogEntry[]): Promise<void> {
    this.logs = logs;
    this.buildSearchIndex();
  }

  async addLog(log: AuditLogEntry): Promise<void> {
    this.logs.push(log);
    this.updateSearchIndex(log);
  }

  private buildSearchIndex(): void {
    this.indexedLogs.clear();
    
    this.logs.forEach(log => {
      // Index by event type
      const eventTypeKey = `eventType:${log.eventType}`;
      if (!this.indexedLogs.has(eventTypeKey)) {
        this.indexedLogs.set(eventTypeKey, []);
      }
      this.indexedLogs.get(eventTypeKey)!.push(log);

      // Index by user ID
      if (log.userId) {
        const userKey = `userId:${log.userId}`;
        if (!this.indexedLogs.has(userKey)) {
          this.indexedLogs.set(userKey, []);
        }
        this.indexedLogs.get(userKey)!.push(log);
      }

      // Index by session ID
      if (log.sessionId) {
        const sessionKey = `sessionId:${log.sessionId}`;
        if (!this.indexedLogs.has(sessionKey)) {
          this.indexedLogs.set(sessionKey, []);
        }
        this.indexedLogs.get(sessionKey)!.push(log);
      }

      // Index by decision type
      if (log.data.decision) {
        const decisionKey = `decision:${log.data.decision.decision}`;
        if (!this.indexedLogs.has(decisionKey)) {
          this.indexedLogs.set(decisionKey, []);
        }
        this.indexedLogs.get(decisionKey)!.push(log);
      }
    });
  }

  private updateSearchIndex(log: AuditLogEntry): void {
    // Update existing indexes with new log
    const eventTypeKey = `eventType:${log.eventType}`;
    if (!this.indexedLogs.has(eventTypeKey)) {
      this.indexedLogs.set(eventTypeKey, []);
    }
    this.indexedLogs.get(eventTypeKey)!.push(log);

    if (log.userId) {
      const userKey = `userId:${log.userId}`;
      if (!this.indexedLogs.has(userKey)) {
        this.indexedLogs.set(userKey, []);
      }
      this.indexedLogs.get(userKey)!.push(log);
    }

    if (log.sessionId) {
      const sessionKey = `sessionId:${log.sessionId}`;
      if (!this.indexedLogs.has(sessionKey)) {
        this.indexedLogs.set(sessionKey, []);
      }
      this.indexedLogs.get(sessionKey)!.push(log);
    }

    if (log.data.decision) {
      const decisionKey = `decision:${log.data.decision.decision}`;
      if (!this.indexedLogs.has(decisionKey)) {
        this.indexedLogs.set(decisionKey, []);
      }
      this.indexedLogs.get(decisionKey)!.push(log);
    }
  }

  async filterLogs(
    filter: LogFilter,
    page: number = 1,
    pageSize: number = 100
  ): Promise<LogExplorerResult> {
    const startTime = Date.now();
    
    let filteredLogs = [...this.logs];

    // Apply time range filter
    if (filter.startTime) {
      filteredLogs = filteredLogs.filter(log => log.timestamp >= filter.startTime!);
    }
    if (filter.endTime) {
      filteredLogs = filteredLogs.filter(log => log.timestamp <= filter.endTime!);
    }

    // Apply event type filter
    if (filter.eventType && filter.eventType.length > 0) {
      filteredLogs = filteredLogs.filter(log => filter.eventType!.includes(log.eventType));
    }

    // Apply user ID filter
    if (filter.userId) {
      filteredLogs = filteredLogs.filter(log => log.userId === filter.userId);
    }

    // Apply session ID filter
    if (filter.sessionId) {
      filteredLogs = filteredLogs.filter(log => log.sessionId === filter.sessionId);
    }

    // Apply decision filter
    if (filter.decision && filter.decision.length > 0) {
      filteredLogs = filteredLogs.filter(log => 
        log.data.decision && filter.decision!.includes(log.data.decision.decision)
      );
    }

    // Apply risk score range filter
    if (filter.riskScoreMin !== undefined || filter.riskScoreMax !== undefined) {
      filteredLogs = filteredLogs.filter(log => {
        if (!log.data.decision) return false;
        const riskScore = log.data.decision.riskScore;
        
        if (filter.riskScoreMin !== undefined && riskScore < filter.riskScoreMin) return false;
        if (filter.riskScoreMax !== undefined && riskScore > filter.riskScoreMax) return false;
        
        return true;
      });
    }

    // Apply attack type filter
    if (filter.attackType && filter.attackType.length > 0) {
      filteredLogs = filteredLogs.filter(log => 
        log.data.decision && 
        filter.attackType!.includes(log.data.decision.attackCategory.type)
      );
    }

    // Apply severity filter (based on risk score)
    if (filter.severity && filter.severity.length > 0) {
      filteredLogs = filteredLogs.filter(log => {
        if (!log.data.decision) return false;
        const severity = this.calculateSeverity(log.data.decision.riskScore);
        return filter.severity!.includes(severity);
      });
    }

    // Sort by timestamp (newest first)
    filteredLogs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const totalPages = Math.ceil(filteredLogs.length / pageSize);
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedLogs = filteredLogs.slice(startIndex, endIndex);

    const executionTime = Math.max(1, Date.now() - startTime); // Ensure at least 1ms

    return {
      logs: paginatedLogs,
      totalCount: this.logs.length,
      filteredCount: filteredLogs.length,
      pagination: {
        page,
        pageSize,
        totalPages
      },
      executionTime
    };
  }

  async searchLogs(
    query: LogSearchQuery,
    filter?: LogFilter,
    page: number = 1,
    pageSize: number = 100
  ): Promise<LogExplorerResult> {
    const startTime = Date.now();
    
    // First apply any filters
    let searchableLogs = this.logs;
    if (filter) {
      const filterResult = await this.filterLogs(filter, 1, this.logs.length);
      searchableLogs = filterResult.logs;
    }

    // Apply search query
    const searchResults = searchableLogs.filter(log => {
      return query.searchFields.some(field => {
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

        if (!query.caseSensitive) {
          searchValue = searchValue.toLowerCase();
          query.searchTerm = query.searchTerm.toLowerCase();
        }

        if (query.useRegex) {
          try {
            const regex = new RegExp(query.searchTerm, query.caseSensitive ? 'g' : 'gi');
            return regex.test(searchValue);
          } catch {
            // If regex is invalid, fall back to string search
            return searchValue.includes(query.searchTerm);
          }
        } else {
          return searchValue.includes(query.searchTerm);
        }
      });
    });

    // Sort by timestamp (newest first)
    searchResults.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const totalPages = Math.ceil(searchResults.length / pageSize);
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    const paginatedResults = searchResults.slice(startIndex, endIndex);

    const executionTime = Math.max(1, Date.now() - startTime); // Ensure at least 1ms

    return {
      logs: paginatedResults,
      totalCount: this.logs.length,
      filteredCount: searchResults.length,
      pagination: {
        page,
        pageSize,
        totalPages
      },
      executionTime
    };
  }

  async exportLogs(
    logs: AuditLogEntry[],
    options: LogExportOptions
  ): Promise<string> {
    switch (options.format) {
      case 'json':
        return this.exportAsJson(logs, options);
      case 'csv':
        return this.exportAsCsv(logs, options);
      case 'siem':
        return this.exportAsSiem(logs, options);
      default:
        throw new Error(`Unsupported export format: ${options.format}`);
    }
  }

  private exportAsJson(logs: AuditLogEntry[], options: LogExportOptions): string {
    const exportData = logs.map(log => {
      const exportLog: any = {
        id: log.id,
        timestamp: this.formatDate(log.timestamp, options.dateFormat),
        eventType: log.eventType,
        userId: log.userId,
        sessionId: log.sessionId,
        data: log.data
      };

      if (options.includeMetadata) {
        exportLog.metadata = log.metadata;
      }

      return exportLog;
    });

    return JSON.stringify(exportData, null, 2);
  }

  private exportAsCsv(logs: AuditLogEntry[], options: LogExportOptions): string {
    const separator = options.fieldSeparator || ',';
    const headers = [
      'id',
      'timestamp',
      'eventType',
      'userId',
      'sessionId',
      'decision',
      'riskScore',
      'attackType',
      'explanation',
      'prompt'
    ];

    if (options.includeMetadata) {
      headers.push('processingTime', 'ipAddress', 'userAgent');
    }

    const csvLines = [headers.join(separator)];

    logs.forEach(log => {
      const row = [
        log.id,
        this.formatDate(log.timestamp, options.dateFormat),
        log.eventType,
        log.userId || '',
        log.sessionId || '',
        log.data.decision?.decision || '',
        log.data.decision?.riskScore?.toString() || '',
        log.data.decision?.attackCategory?.type || '',
        this.escapeCsvField(log.data.decision?.explanation || ''),
        this.escapeCsvField(log.data.prompt || '')
      ];

      if (options.includeMetadata) {
        row.push(
          log.metadata.processingTime?.toString() || '',
          log.metadata.ipAddress || '',
          log.metadata.userAgent || ''
        );
      }

      csvLines.push(row.join(separator));
    });

    return csvLines.join('\n');
  }

  private exportAsSiem(logs: AuditLogEntry[], options: LogExportOptions): string {
    // SIEM format (CEF - Common Event Format)
    const siemLines = logs.map(log => {
      const timestamp = this.formatDate(log.timestamp, 'unix');
      const severity = log.data.decision ? this.calculateSeverityNumber(log.data.decision.riskScore) : 1;
      
      return `CEF:0|TrustLens|AI Security Platform|1.0|${log.eventType}|${log.eventType}|${severity}|` +
             `rt=${timestamp} ` +
             `src=${log.metadata.ipAddress || 'unknown'} ` +
             `suser=${log.userId || 'unknown'} ` +
             `cs1=${log.data.decision?.decision || 'N/A'} cs1Label=Decision ` +
             `cn1=${log.data.decision?.riskScore || 0} cn1Label=RiskScore ` +
             `cs2=${log.data.decision?.attackCategory?.type || 'N/A'} cs2Label=AttackType ` +
             `msg=${this.escapeCefField(log.data.decision?.explanation || log.eventType)}`;
    });

    return siemLines.join('\n');
  }

  private formatDate(date: Date, format: 'iso' | 'unix' | 'human'): string {
    switch (format) {
      case 'iso':
        return date.toISOString();
      case 'unix':
        return Math.floor(date.getTime() / 1000).toString();
      case 'human':
        return date.toLocaleString();
      default:
        return date.toISOString();
    }
  }

  private escapeCsvField(field: string): string {
    if (field.includes(',') || field.includes('"') || field.includes('\n')) {
      return `"${field.replace(/"/g, '""')}"`;
    }
    return field;
  }

  private escapeCefField(field: string): string {
    return field.replace(/[=\\|]/g, '\\$&');
  }

  private calculateSeverity(riskScore: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    if (riskScore >= 80) return 'CRITICAL';
    if (riskScore >= 60) return 'HIGH';
    if (riskScore >= 30) return 'MEDIUM';
    return 'LOW';
  }

  private calculateSeverityNumber(riskScore: number): number {
    if (riskScore >= 80) return 10; // Critical
    if (riskScore >= 60) return 7;  // High
    if (riskScore >= 30) return 4;  // Medium
    return 1; // Low
  }

  async generateLogStatistics(): Promise<LogStatistics> {
    const eventTypeDistribution: Record<string, number> = {};
    const severityDistribution: Record<string, number> = {};
    const decisionDistribution: Record<string, number> = {};
    const userCounts: Record<string, number> = {};
    
    let totalRiskScore = 0;
    let riskScoreCount = 0;
    let earliest = new Date();
    let latest = new Date(0);

    this.logs.forEach(log => {
      // Event type distribution
      eventTypeDistribution[log.eventType] = (eventTypeDistribution[log.eventType] || 0) + 1;

      // Time range
      if (log.timestamp < earliest) earliest = log.timestamp;
      if (log.timestamp > latest) latest = log.timestamp;

      // User counts
      if (log.userId) {
        userCounts[log.userId] = (userCounts[log.userId] || 0) + 1;
      }

      // Decision and severity distribution
      if (log.data.decision) {
        const decision = log.data.decision.decision;
        decisionDistribution[decision] = (decisionDistribution[decision] || 0) + 1;

        const severity = this.calculateSeverity(log.data.decision.riskScore);
        severityDistribution[severity] = (severityDistribution[severity] || 0) + 1;

        totalRiskScore += log.data.decision.riskScore;
        riskScoreCount++;
      }
    });

    const topUsers = Object.entries(userCounts)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .map(([userId, count]) => ({ userId, count }));

    return {
      totalLogs: this.logs.length,
      eventTypeDistribution,
      severityDistribution,
      decisionDistribution,
      timeRange: { earliest, latest },
      averageRiskScore: riskScoreCount > 0 ? totalRiskScore / riskScoreCount : 0,
      topUsers
    };
  }

  // SOC-style formatting methods
  formatLogForSOC(log: AuditLogEntry): string {
    const timestamp = log.timestamp.toISOString().substring(0, 19).replace('T', ' ');
    const eventType = log.eventType.padEnd(15);
    const decision = log.data.decision?.decision || 'N/A';
    const riskScore = log.data.decision?.riskScore?.toString().padStart(3) || 'N/A';
    const userId = (log.userId || 'anonymous').substring(0, 10).padEnd(10);
    
    return `${timestamp} ${eventType} ${decision} ${riskScore}% ${userId}`;
  }

  formatLogStatisticsForSOC(stats: LogStatistics): string {
    const lines = [
      `Total Logs: ${stats.totalLogs}`,
      `Time Range: ${stats.timeRange.earliest.toISOString()} - ${stats.timeRange.latest.toISOString()}`,
      `Average Risk Score: ${stats.averageRiskScore.toFixed(1)}%`,
      '',
      'Event Types:',
      ...Object.entries(stats.eventTypeDistribution).map(([type, count]) => 
        `  ${type.padEnd(20)}: ${count}`
      ),
      '',
      'Severity Distribution:',
      ...Object.entries(stats.severityDistribution).map(([severity, count]) => 
        `  ${severity.padEnd(8)}: ${count}`
      ),
      '',
      'Top Users:',
      ...stats.topUsers.map(user => 
        `  ${user.userId.padEnd(15)}: ${user.count} events`
      )
    ];
    
    return lines.join('\n');
  }
}