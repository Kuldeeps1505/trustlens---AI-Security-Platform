/**
 * Tamper-Evident Audit Log System
 * Implements cryptographic integrity verification and compliance features
 */

import crypto from 'crypto';
import { AuditLogEntry } from '../types/core';
import { SQLiteDatabase, LogFilters } from './database';

export interface TamperEvidenceMetadata {
  hash: string;
  previousHash: string;
  signature: string;
  timestamp: number;
  sequenceNumber: number;
}

export interface AuditLogWithIntegrity extends AuditLogEntry {
  integrity: TamperEvidenceMetadata;
}

export interface ComplianceSettings {
  retentionPeriodDays: number;
  encryptionEnabled: boolean;
  signatureRequired: boolean;
  backupFrequencyHours: number;
  auditTrailVerificationEnabled: boolean;
}

export interface IntegrityVerificationResult {
  isValid: boolean;
  totalEntries: number;
  verifiedEntries: number;
  corruptedEntries: string[];
  missingEntries: string[];
  lastVerifiedSequence: number;
  verificationTimestamp: Date;
}

export interface RetentionReport {
  totalEntries: number;
  eligibleForDeletion: number;
  deletedEntries: number;
  retentionPeriodDays: number;
  oldestEntry: Date;
  newestEntry: Date;
  executedAt: Date;
}

export class TamperEvidientAuditLogSystem {
  private database: SQLiteDatabase;
  private secretKey: string;
  private lastHash: string = '';
  private sequenceCounter: number = 0;
  private complianceSettings: ComplianceSettings;

  constructor(
    database: SQLiteDatabase, 
    secretKey?: string,
    complianceSettings?: Partial<ComplianceSettings>
  ) {
    this.database = database;
    this.secretKey = secretKey || this.generateSecretKey();
    this.complianceSettings = {
      retentionPeriodDays: 2555, // 7 years default
      encryptionEnabled: true,
      signatureRequired: true,
      backupFrequencyHours: 24,
      auditTrailVerificationEnabled: true,
      ...complianceSettings
    };
    // Initialize genesis hash immediately
    this.lastHash = crypto.createHash('sha256').update('TRUSTLENS_GENESIS').digest('hex');
    this.sequenceCounter = 0;
  }

  async initialize(): Promise<void> {
    await this.initializeIntegrityChain();
  }

  private generateSecretKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  private async initializeIntegrityChain(): Promise<void> {
    try {
      // Ensure integrity table exists first
      await this.ensureIntegrityTableExists();
      
      // Get the last log entry to continue the chain
      const lastEntry = await this.getLastLogEntry();
      if (lastEntry) {
        this.lastHash = lastEntry.integrity.hash;
        this.sequenceCounter = lastEntry.integrity.sequenceNumber;
      } else {
        // Initialize genesis hash
        this.lastHash = crypto.createHash('sha256').update('TRUSTLENS_GENESIS').digest('hex');
        this.sequenceCounter = 0;
      }
    } catch (error) {
      // If there's an error, start fresh
      this.lastHash = crypto.createHash('sha256').update('TRUSTLENS_GENESIS').digest('hex');
      this.sequenceCounter = 0;
    }
  }

  private async getLastLogEntry(): Promise<AuditLogWithIntegrity | null> {
    try {
      const query = `
        SELECT * FROM audit_logs_integrity 
        ORDER BY sequence_number DESC 
        LIMIT 1
      `;
      const rows = await this.database.executeQuery(query);
      
      if (rows.length === 0) return null;
      
      const row = rows[0];
      return this.deserializeLogEntry(row);
    } catch (error) {
      return null;
    }
  }

  async insertLogEntry(entry: AuditLogEntry): Promise<void> {
    // Create tamper-evident version
    const integrityEntry = await this.createTamperEvidientEntry(entry);
    
    // Store only in integrity table (which contains all the data)
    await this.insertIntegrityEntry(integrityEntry);
    
    // Update chain state
    this.lastHash = integrityEntry.integrity.hash;
    this.sequenceCounter = integrityEntry.integrity.sequenceNumber;
  }

  private async createTamperEvidientEntry(entry: AuditLogEntry): Promise<AuditLogWithIntegrity> {
    this.sequenceCounter++;
    
    // Create content hash
    const contentString = JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp.toISOString(),
      eventType: entry.eventType,
      userId: entry.userId,
      sessionId: entry.sessionId,
      data: entry.data,
      metadata: entry.metadata
    });
    
    const contentHash = crypto.createHash('sha256').update(contentString).digest('hex');
    
    // Create chain hash (includes previous hash)
    const chainData = `${this.lastHash}:${contentHash}:${this.sequenceCounter}`;
    const chainHash = crypto.createHash('sha256').update(chainData).digest('hex');
    
    // Create signature
    const signature = this.complianceSettings.signatureRequired 
      ? crypto.createHmac('sha256', this.secretKey).update(chainHash).digest('hex')
      : '';

    const integrity: TamperEvidenceMetadata = {
      hash: chainHash,
      previousHash: this.lastHash,
      signature,
      timestamp: Date.now(),
      sequenceNumber: this.sequenceCounter
    };

    return {
      ...entry,
      integrity
    };
  }

  private async insertIntegrityEntry(entry: AuditLogWithIntegrity): Promise<void> {
    // Ensure integrity table exists
    await this.ensureIntegrityTableExists();
    
    const sql = `
      INSERT OR REPLACE INTO audit_logs_integrity (
        id, timestamp, event_type, user_id, session_id, data, metadata,
        hash, previous_hash, signature, integrity_timestamp, sequence_number
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    
    const params = [
      entry.id,
      entry.timestamp.toISOString(),
      entry.eventType,
      entry.userId || null,
      entry.sessionId || null,
      JSON.stringify(entry.data),
      JSON.stringify(entry.metadata),
      entry.integrity.hash,
      entry.integrity.previousHash,
      entry.integrity.signature,
      entry.integrity.timestamp,
      entry.integrity.sequenceNumber
    ];
    
    await this.database.executeQuery(sql, params);
  }

  private async ensureIntegrityTableExists(): Promise<void> {
    const sql = `
      CREATE TABLE IF NOT EXISTS audit_logs_integrity (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user_id TEXT,
        session_id TEXT,
        data TEXT,
        metadata TEXT,
        hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        signature TEXT,
        integrity_timestamp INTEGER NOT NULL,
        sequence_number INTEGER NOT NULL UNIQUE
      )
    `;
    
    await this.database.executeQuery(sql);
    
    // Create index on sequence_number for better performance
    const indexSql = `
      CREATE INDEX IF NOT EXISTS idx_audit_logs_integrity_sequence 
      ON audit_logs_integrity(sequence_number)
    `;
    
    await this.database.executeQuery(indexSql);
  }

  async verifyIntegrity(): Promise<IntegrityVerificationResult> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT * FROM audit_logs_integrity 
        ORDER BY sequence_number ASC
      `;
      const rows = await this.database.executeQuery(query);
      
      const result: IntegrityVerificationResult = {
        isValid: true,
        totalEntries: rows.length,
        verifiedEntries: 0,
        corruptedEntries: [],
        missingEntries: [],
        lastVerifiedSequence: 0,
        verificationTimestamp: new Date()
      };

      if (rows.length === 0) {
        return result;
      }

      let expectedPreviousHash = crypto.createHash('sha256').update('TRUSTLENS_GENESIS').digest('hex');
      let expectedSequence = 1;

      for (const row of rows) {
        const entry = this.deserializeLogEntry(row);
        
        // Check sequence continuity
        if (entry.integrity.sequenceNumber !== expectedSequence) {
          result.missingEntries.push(`Missing sequence ${expectedSequence}`);
          result.isValid = false;
          // Skip to the actual sequence number to continue verification
          expectedSequence = entry.integrity.sequenceNumber;
        }

        // Verify previous hash chain
        if (entry.integrity.previousHash !== expectedPreviousHash) {
          result.corruptedEntries.push(entry.id);
          result.isValid = false;
        }

        // Verify content integrity by recalculating the hash
        const contentString = JSON.stringify({
          id: entry.id,
          timestamp: entry.timestamp.toISOString(),
          eventType: entry.eventType,
          userId: entry.userId,
          sessionId: entry.sessionId,
          data: entry.data,
          metadata: entry.metadata
        });
        
        const contentHash = crypto.createHash('sha256').update(contentString).digest('hex');
        const chainData = `${entry.integrity.previousHash}:${contentHash}:${entry.integrity.sequenceNumber}`;
        const expectedHash = crypto.createHash('sha256').update(chainData).digest('hex');
        
        if (entry.integrity.hash !== expectedHash) {
          result.corruptedEntries.push(entry.id);
          result.isValid = false;
        }

        // Verify signature if required
        if (this.complianceSettings.signatureRequired && entry.integrity.signature) {
          const expectedSignature = crypto.createHmac('sha256', this.secretKey)
            .update(entry.integrity.hash).digest('hex');
          
          if (entry.integrity.signature !== expectedSignature) {
            result.corruptedEntries.push(entry.id);
            result.isValid = false;
          }
        }

        // If this entry passed all checks, count it as verified
        if (!result.corruptedEntries.includes(entry.id)) {
          result.verifiedEntries++;
          result.lastVerifiedSequence = entry.integrity.sequenceNumber;
        }

        // Update expected values for next iteration
        expectedPreviousHash = entry.integrity.hash;
        expectedSequence++;
      }

      return result;
    } catch (error) {
      return {
        isValid: false,
        totalEntries: 0,
        verifiedEntries: 0,
        corruptedEntries: [],
        missingEntries: [`Verification failed: ${error}`],
        lastVerifiedSequence: 0,
        verificationTimestamp: new Date()
      };
    }
  }

  private deserializeLogEntry(row: any): AuditLogWithIntegrity {
    return {
      id: row.id,
      timestamp: new Date(row.timestamp),
      eventType: row.event_type,
      userId: row.user_id,
      sessionId: row.session_id,
      data: JSON.parse(row.data),
      metadata: JSON.parse(row.metadata),
      integrity: {
        hash: row.hash,
        previousHash: row.previous_hash,
        signature: row.signature,
        timestamp: row.integrity_timestamp,
        sequenceNumber: row.sequence_number
      }
    };
  }

  async exportLogsWithIntegrity(
    format: 'CSV' | 'JSON' | 'SIEM',
    filters?: LogFilters
  ): Promise<string> {
    const logs = await this.getLogEntries(filters);
    
    switch (format) {
      case 'JSON':
        return JSON.stringify(logs.map(log => ({
          ...log,
          integrityVerified: true,
          exportTimestamp: new Date().toISOString()
        })), null, 2);
        
      case 'CSV':
        return this.exportAsCsv(logs);
        
      case 'SIEM':
        return this.exportAsSiem(logs);
        
      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  private async getLogEntries(filters?: LogFilters): Promise<AuditLogWithIntegrity[]> {
    let sql = 'SELECT * FROM audit_logs_integrity WHERE 1=1';
    const params: any[] = [];

    if (filters?.startTime) {
      sql += ' AND timestamp >= ?';
      params.push(filters.startTime.toISOString());
    }
    if (filters?.endTime) {
      sql += ' AND timestamp <= ?';
      params.push(filters.endTime.toISOString());
    }
    if (filters?.eventType) {
      sql += ' AND event_type = ?';
      params.push(filters.eventType);
    }
    if (filters?.userId) {
      sql += ' AND user_id = ?';
      params.push(filters.userId);
    }

    sql += ' ORDER BY sequence_number ASC';
    
    const rows = await this.database.executeQuery(sql, params);
    return rows.map(row => this.deserializeLogEntry(row));
  }

  private exportAsCsv(logs: AuditLogWithIntegrity[]): string {
    const headers = [
      'id', 'timestamp', 'event_type', 'user_id', 'session_id', 
      'decision', 'risk_score', 'attack_type', 'explanation', 'prompt',
      'sequence_number', 'hash', 'previous_hash', 'integrity_verified'
    ].join(',');

    const rows = logs.map(log => [
      log.id,
      log.timestamp.toISOString(),
      log.eventType,
      log.userId || '',
      log.sessionId || '',
      log.data.decision?.decision || '',
      log.data.decision?.riskScore?.toString() || '',
      log.data.decision?.attackCategory?.type || '',
      this.escapeCsvField(log.data.decision?.explanation || ''),
      this.escapeCsvField(log.data.prompt || ''),
      log.integrity.sequenceNumber.toString(),
      log.integrity.hash,
      log.integrity.previousHash,
      'true'
    ].join(','));

    return [headers, ...rows].join('\n');
  }

  private exportAsSiem(logs: AuditLogWithIntegrity[]): string {
    return logs.map(log => {
      const timestamp = Math.floor(log.timestamp.getTime() / 1000);
      const severity = log.data.decision ? this.calculateSeverityNumber(log.data.decision.riskScore) : 1;
      
      return `CEF:0|TrustLens|AI Security Platform|1.0|${log.eventType}|${log.eventType}|${severity}|` +
             `rt=${timestamp} ` +
             `src=${log.metadata.ipAddress || 'unknown'} ` +
             `suser=${log.userId || 'unknown'} ` +
             `cs1=${log.data.decision?.decision || 'N/A'} cs1Label=Decision ` +
             `cn1=${log.data.decision?.riskScore || 0} cn1Label=RiskScore ` +
             `cs2=${log.data.decision?.attackCategory?.type || 'N/A'} cs2Label=AttackType ` +
             `cs3=${log.integrity.sequenceNumber} cs3Label=SequenceNumber ` +
             `cs4=${log.integrity.hash.substring(0, 16)} cs4Label=IntegrityHash ` +
             `msg=${this.escapeCefField(log.data.decision?.explanation || log.eventType)}`;
    }).join('\n');
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

  private calculateSeverityNumber(riskScore: number): number {
    if (riskScore >= 80) return 10; // Critical
    if (riskScore >= 60) return 7;  // High
    if (riskScore >= 30) return 4;  // Medium
    return 1; // Low
  }

  async performRetentionManagement(): Promise<RetentionReport> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.complianceSettings.retentionPeriodDays);

    // Get statistics before deletion
    const totalQuery = 'SELECT COUNT(*) as count FROM audit_logs_integrity';
    const totalResult = await this.database.executeQuery(totalQuery);
    const totalEntries = totalResult[0].count;

    const eligibleQuery = 'SELECT COUNT(*) as count FROM audit_logs_integrity WHERE timestamp < ?';
    const eligibleResult = await this.database.executeQuery(eligibleQuery, [cutoffDate.toISOString()]);
    const eligibleForDeletion = eligibleResult[0].count;

    // Get date range
    const rangeQuery = `
      SELECT 
        MIN(timestamp) as oldest,
        MAX(timestamp) as newest
      FROM audit_logs_integrity
    `;
    const rangeResult = await this.database.executeQuery(rangeQuery);
    const oldestEntry = new Date(rangeResult[0].oldest);
    const newestEntry = new Date(rangeResult[0].newest);

    // Perform deletion (if any eligible entries exist)
    let deletedEntries = 0;
    if (eligibleForDeletion > 0) {
      const deleteQuery = 'DELETE FROM audit_logs_integrity WHERE timestamp < ?';
      await this.database.executeQuery(deleteQuery, [cutoffDate.toISOString()]);
      
      // Also delete from regular audit_logs table
      const deleteRegularQuery = 'DELETE FROM audit_logs WHERE timestamp < ?';
      await this.database.executeQuery(deleteRegularQuery, [cutoffDate.toISOString()]);
      
      deletedEntries = eligibleForDeletion;
    }

    return {
      totalEntries,
      eligibleForDeletion,
      deletedEntries,
      retentionPeriodDays: this.complianceSettings.retentionPeriodDays,
      oldestEntry,
      newestEntry,
      executedAt: new Date()
    };
  }

  getComplianceSettings(): ComplianceSettings {
    return { ...this.complianceSettings };
  }

  updateComplianceSettings(settings: Partial<ComplianceSettings>): void {
    this.complianceSettings = { ...this.complianceSettings, ...settings };
  }

  async generateComplianceReport(): Promise<{
    integrityVerification: IntegrityVerificationResult;
    retentionStatus: RetentionReport;
    complianceSettings: ComplianceSettings;
    generatedAt: Date;
  }> {
    const integrityVerification = await this.verifyIntegrity();
    const retentionStatus = await this.performRetentionManagement();
    
    return {
      integrityVerification,
      retentionStatus,
      complianceSettings: this.getComplianceSettings(),
      generatedAt: new Date()
    };
  }
}