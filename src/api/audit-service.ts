/**
 * Enhanced Audit Service with Tamper-Evident Logging and Compliance Features
 * Integrates with the TamperEvidientAuditLogSystem for secure audit logging
 */

import { AuditLogEntry } from '../types/core';
import { SQLiteDatabase, LogFilters } from '../data/database';
import { TamperEvidientAuditLogSystem, ComplianceSettings, IntegrityVerificationResult, RetentionReport } from '../data/audit-log-system';
import { SecurityLogExplorer, LogFilter, LogSearchQuery, LogExportOptions, LogExplorerResult } from '../ui/log-explorer';

export interface AuditServiceConfig {
  database: SQLiteDatabase;
  secretKey?: string;
  complianceSettings?: Partial<ComplianceSettings>;
}

export interface BulkExportOptions {
  format: 'CSV' | 'JSON' | 'SIEM';
  includeIntegrity: boolean;
  filters?: LogFilters;
  batchSize?: number;
}

export interface AuditServiceStatus {
  isHealthy: boolean;
  totalLogs: number;
  integrityStatus: 'VERIFIED' | 'CORRUPTED' | 'UNKNOWN';
  lastVerification: Date | null;
  complianceStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'WARNING';
  issues: string[];
}

export class EnhancedAuditService {
  private tamperEvidientSystem: TamperEvidientAuditLogSystem;
  private logExplorer: SecurityLogExplorer;
  private database: SQLiteDatabase;
  private lastHealthCheck: Date | null = null;
  private healthCheckInterval: NodeJS.Timeout | null = null;

  constructor(config: AuditServiceConfig) {
    this.database = config.database;
    this.tamperEvidientSystem = new TamperEvidientAuditLogSystem(
      config.database,
      config.secretKey,
      config.complianceSettings
    );
    this.logExplorer = new SecurityLogExplorer();
    this.startHealthMonitoring();
  }

  private startHealthMonitoring(): void {
    // Perform health checks every hour
    this.healthCheckInterval = setInterval(async () => {
      await this.performHealthCheck();
    }, 60 * 60 * 1000);
  }

  async initialize(): Promise<void> {
    await this.database.connect();
    await this.loadLogsIntoExplorer();
    await this.performHealthCheck();
  }

  async shutdown(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    await this.database.disconnect();
  }

  private async loadLogsIntoExplorer(): Promise<void> {
    try {
      const logs = await this.database.getLogEntries();
      await this.logExplorer.loadLogs(logs);
    } catch (error) {
      console.error('Failed to load logs into explorer:', error);
    }
  }

  async logEvent(entry: AuditLogEntry): Promise<void> {
    try {
      // Insert with tamper-evident protection
      await this.tamperEvidientSystem.insertLogEntry(entry);
      
      // Update log explorer
      await this.logExplorer.addLog(entry);
    } catch (error) {
      console.error('Failed to log audit event:', error);
      // In a production system, this might trigger alerts
      throw error;
    }
  }

  async searchLogs(
    query: LogSearchQuery,
    filter?: LogFilter,
    page: number = 1,
    pageSize: number = 100
  ): Promise<LogExplorerResult> {
    return await this.logExplorer.searchLogs(query, filter, page, pageSize);
  }

  async filterLogs(
    filter: LogFilter,
    page: number = 1,
    pageSize: number = 100
  ): Promise<LogExplorerResult> {
    return await this.logExplorer.filterLogs(filter, page, pageSize);
  }

  async exportLogs(options: BulkExportOptions): Promise<string> {
    if (options.includeIntegrity) {
      // Use tamper-evident system for integrity-verified export
      return await this.tamperEvidientSystem.exportLogsWithIntegrity(
        options.format,
        options.filters
      );
    } else {
      // Use regular database export
      return await this.database.exportLogs(options.format, options.filters);
    }
  }

  async bulkExportLogs(options: BulkExportOptions): Promise<AsyncGenerator<string, void, unknown>> {
    const batchSize = options.batchSize || 1000;
    let offset = 0;
    
    return (async function* (this: EnhancedAuditService) {
      while (true) {
        const batchFilters = {
          ...options.filters,
          // Add pagination logic here if needed
        };
        
        const logs = await this.database.getLogEntries(batchFilters);
        
        if (logs.length === 0) break;
        
        // Export this batch
        const batchLogs = logs.slice(offset, offset + batchSize);
        if (batchLogs.length === 0) break;
        
        if (options.includeIntegrity) {
          // This would need to be implemented in the tamper-evident system
          yield await this.tamperEvidientSystem.exportLogsWithIntegrity(
            options.format,
            batchFilters
          );
        } else {
          yield await this.database.exportLogs(options.format, batchFilters);
        }
        
        offset += batchSize;
        if (offset >= logs.length) break;
      }
    }).call(this);
  }

  async verifyIntegrity(): Promise<IntegrityVerificationResult> {
    return await this.tamperEvidientSystem.verifyIntegrity();
  }

  async performRetentionManagement(): Promise<RetentionReport> {
    const report = await this.tamperEvidientSystem.performRetentionManagement();
    
    // Reload logs into explorer after retention cleanup
    await this.loadLogsIntoExplorer();
    
    return report;
  }

  async generateComplianceReport(): Promise<{
    integrityVerification: IntegrityVerificationResult;
    retentionStatus: RetentionReport;
    complianceSettings: ComplianceSettings;
    serviceStatus: AuditServiceStatus;
    generatedAt: Date;
  }> {
    const baseReport = await this.tamperEvidientSystem.generateComplianceReport();
    const serviceStatus = await this.getServiceStatus();
    
    return {
      ...baseReport,
      serviceStatus,
      generatedAt: new Date()
    };
  }

  async getServiceStatus(): Promise<AuditServiceStatus> {
    const issues: string[] = [];
    let integrityStatus: 'VERIFIED' | 'CORRUPTED' | 'UNKNOWN' = 'UNKNOWN';
    let complianceStatus: 'COMPLIANT' | 'NON_COMPLIANT' | 'WARNING' = 'COMPLIANT';

    try {
      // Check database connectivity
      if (!this.database.isConnected()) {
        issues.push('Database connection lost');
        return {
          isHealthy: false,
          totalLogs: 0,
          integrityStatus: 'UNKNOWN',
          lastVerification: this.lastHealthCheck,
          complianceStatus: 'NON_COMPLIANT',
          issues
        };
      }

      // Get total log count
      const totalQuery = 'SELECT COUNT(*) as count FROM audit_logs';
      const totalResult = await this.database.executeQuery(totalQuery);
      const totalLogs = totalResult[0].count;

      // Verify integrity
      const integrityResult = await this.verifyIntegrity();
      integrityStatus = integrityResult.isValid ? 'VERIFIED' : 'CORRUPTED';
      
      if (!integrityResult.isValid) {
        issues.push(`Integrity verification failed: ${integrityResult.corruptedEntries.length} corrupted entries`);
        complianceStatus = 'NON_COMPLIANT';
      }

      // Check compliance settings
      const settings = this.tamperEvidientSystem.getComplianceSettings();
      if (!settings.signatureRequired) {
        issues.push('Digital signatures not required - compliance risk');
        if (complianceStatus === 'COMPLIANT') complianceStatus = 'WARNING';
      }

      if (!settings.encryptionEnabled) {
        issues.push('Encryption not enabled - compliance risk');
        if (complianceStatus === 'COMPLIANT') complianceStatus = 'WARNING';
      }

      // Check retention policy
      if (settings.retentionPeriodDays < 2555) { // Less than 7 years
        issues.push('Retention period may not meet regulatory requirements');
        if (complianceStatus === 'COMPLIANT') complianceStatus = 'WARNING';
      }

      this.lastHealthCheck = new Date();

      return {
        isHealthy: issues.length === 0,
        totalLogs,
        integrityStatus,
        lastVerification: this.lastHealthCheck,
        complianceStatus,
        issues
      };
    } catch (error) {
      issues.push(`Health check failed: ${error}`);
      return {
        isHealthy: false,
        totalLogs: 0,
        integrityStatus: 'UNKNOWN',
        lastVerification: this.lastHealthCheck,
        complianceStatus: 'NON_COMPLIANT',
        issues
      };
    }
  }

  private async performHealthCheck(): Promise<void> {
    try {
      await this.getServiceStatus();
    } catch (error) {
      console.error('Health check failed:', error);
    }
  }

  // SOC-style formatting methods
  async generateSOCReport(): Promise<string> {
    const stats = await this.logExplorer.generateLogStatistics();
    const status = await this.getServiceStatus();
    const integrity = await this.verifyIntegrity();
    
    const lines = [
      '=== TrustLens Audit Log System - SOC Report ===',
      `Generated: ${new Date().toISOString()}`,
      `Status: ${status.isHealthy ? 'HEALTHY' : 'DEGRADED'}`,
      `Integrity: ${status.integrityStatus}`,
      `Compliance: ${status.complianceStatus}`,
      '',
      '--- Log Statistics ---',
      this.logExplorer.formatLogStatisticsForSOC(stats),
      '',
      '--- Integrity Verification ---',
      `Total Entries: ${integrity.totalEntries}`,
      `Verified Entries: ${integrity.verifiedEntries}`,
      `Corrupted Entries: ${integrity.corruptedEntries.length}`,
      `Last Verified Sequence: ${integrity.lastVerifiedSequence}`,
      '',
      '--- Issues ---',
      ...status.issues.map(issue => `  ! ${issue}`),
      '',
      '--- Recent Activity ---'
    ];

    // Add recent log entries in SOC format
    const recentLogs = await this.filterLogs({}, 1, 10);
    lines.push(...recentLogs.logs.map(log => this.logExplorer.formatLogForSOC(log)));
    
    return lines.join('\n');
  }

  getComplianceSettings(): ComplianceSettings {
    return this.tamperEvidientSystem.getComplianceSettings();
  }

  updateComplianceSettings(settings: Partial<ComplianceSettings>): void {
    this.tamperEvidientSystem.updateComplianceSettings(settings);
  }
}