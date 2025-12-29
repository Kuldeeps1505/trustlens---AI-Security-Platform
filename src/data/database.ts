/**
 * Database connection and configuration
 * Handles audit logs, metrics, and attack datasets
 */

import sqlite3 from 'sqlite3';
import { AuditLogEntry, SecurityMetrics, AttackDataset } from '../types/core';

// Local type definitions to avoid circular imports
interface BenchmarkConfiguration {
  id: string;
  name: string;
  description: string;
  attackDatasetId: string;
  attackDatasetVersion: string;
  baselineTypes: any[];
  testConditions: any;
  createdAt: Date;
}

interface BenchmarkResult {
  id: string;
  configurationId: string;
  executedAt: Date;
  completedAt: Date;
  status: string;
  baselineResults: any[];
  summary: any;
  reproducibilityHash: string;
}

export interface DatabaseConnection {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
}

export interface AuditLogRepository {
  insertLogEntry(entry: AuditLogEntry): Promise<void>;
  getLogEntries(filters?: LogFilters): Promise<AuditLogEntry[]>;
  exportLogs(format: 'CSV' | 'JSON', filters?: LogFilters): Promise<string>;
}

export interface MetricsRepository {
  insertMetrics(metrics: SecurityMetrics): Promise<void>;
  getMetrics(timeRange: TimeRange): Promise<SecurityMetrics[]>;
  getLatestMetrics(): Promise<SecurityMetrics | null>;
}

export interface AttackDatasetRepository {
  saveDataset(dataset: AttackDataset): Promise<void>;
  getDataset(id: string, version?: string): Promise<AttackDataset | null>;
  listDatasets(): Promise<AttackDataset[]>;
  deleteDataset(id: string, version?: string): Promise<void>;
}

export interface LogFilters {
  startTime?: Date;
  endTime?: Date;
  eventType?: string;
  userId?: string;
  severity?: string;
}

export interface TimeRange {
  start: Date;
  end: Date;
  period?: 'MINUTE' | 'HOUR' | 'DAY';
}

export class SQLiteDatabase implements DatabaseConnection, AuditLogRepository, MetricsRepository, AttackDatasetRepository {
  private db: sqlite3.Database | null = null;
  private connected: boolean = false;
  private dbPath: string;

  constructor(dbPath: string = './trustlens.db') {
    this.dbPath = dbPath;
  }

  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db = new sqlite3.Database(this.dbPath, (err) => {
        if (err) {
          reject(err);
        } else {
          this.connected = true;
          this.initializeTables().then(resolve).catch(reject);
        }
      });
    });
  }

  async disconnect(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.db) {
        this.db.close((err) => {
          if (err) {
            reject(err);
          } else {
            this.connected = false;
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }

  isConnected(): boolean {
    return this.connected;
  }

  private async initializeTables(): Promise<void> {
    const tables = [
      `CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        user_id TEXT,
        session_id TEXT,
        data TEXT,
        metadata TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS audit_logs_integrity (
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
      )`,
      `CREATE TABLE IF NOT EXISTS security_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        period TEXT NOT NULL,
        metrics TEXT NOT NULL,
        trust_score REAL NOT NULL,
        defense_version TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS attack_datasets (
        id TEXT NOT NULL,
        version TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        attacks TEXT NOT NULL,
        metadata TEXT NOT NULL,
        statistics TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (id, version)
      )`,
      `CREATE TABLE IF NOT EXISTS benchmark_configurations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        attack_dataset_id TEXT NOT NULL,
        attack_dataset_version TEXT NOT NULL,
        baseline_types TEXT NOT NULL,
        test_conditions TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS benchmark_results (
        id TEXT PRIMARY KEY,
        configuration_id TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        status TEXT NOT NULL,
        baseline_results TEXT NOT NULL,
        summary TEXT NOT NULL,
        reproducibility_hash TEXT NOT NULL,
        FOREIGN KEY (configuration_id) REFERENCES benchmark_configurations(id)
      )`
    ];

    for (const sql of tables) {
      await this.runQuery(sql);
    }
  }

  private runQuery(sql: string, params: any[] = []): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not connected'));
        return;
      }
      
      this.db.run(sql, params, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  private getQuery(sql: string, params: any[] = []): Promise<any[]> {
    return new Promise((resolve, reject) => {
      if (!this.db) {
        reject(new Error('Database not connected'));
        return;
      }
      
      this.db.all(sql, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  }

  // Public method for dataset API to access query functionality
  async executeQuery(sql: string, params: any[] = []): Promise<any[]> {
    return this.getQuery(sql, params);
  }

  // AuditLogRepository implementation
  async insertLogEntry(entry: AuditLogEntry): Promise<void> {
    const sql = `INSERT INTO audit_logs (id, timestamp, event_type, user_id, session_id, data, metadata) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      entry.id,
      entry.timestamp.toISOString(),
      entry.eventType,
      entry.userId || null,
      entry.sessionId || null,
      JSON.stringify(entry.data),
      JSON.stringify(entry.metadata)
    ];
    
    await this.runQuery(sql, params);
  }

  async getLogEntries(filters?: LogFilters): Promise<AuditLogEntry[]> {
    let sql = 'SELECT * FROM audit_logs WHERE 1=1';
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

    sql += ' ORDER BY timestamp DESC';
    
    const rows = await this.getQuery(sql, params);
    return rows.map(row => ({
      id: row.id,
      timestamp: new Date(row.timestamp),
      eventType: row.event_type,
      userId: row.user_id,
      sessionId: row.session_id,
      data: JSON.parse(row.data),
      metadata: JSON.parse(row.metadata)
    }));
  }

  async exportLogs(format: 'CSV' | 'JSON', filters?: LogFilters): Promise<string> {
    const logs = await this.getLogEntries(filters);
    
    if (format === 'JSON') {
      return JSON.stringify(logs, null, 2);
    } else {
      // CSV format
      const headers = 'id,timestamp,event_type,user_id,session_id,data,metadata\n';
      const rows = logs.map(log => 
        `${log.id},${log.timestamp.toISOString()},${log.eventType},${log.userId || ''},${log.sessionId || ''},"${JSON.stringify(log.data).replace(/"/g, '""')}","${JSON.stringify(log.metadata).replace(/"/g, '""')}"`
      ).join('\n');
      return headers + rows;
    }
  }

  // MetricsRepository implementation
  async insertMetrics(metrics: SecurityMetrics): Promise<void> {
    const sql = `INSERT INTO security_metrics (timestamp, period, metrics, trust_score, defense_version) 
                 VALUES (?, ?, ?, ?, ?)`;
    const params = [
      metrics.timestamp.toISOString(),
      metrics.period,
      JSON.stringify(metrics.metrics),
      metrics.trustScore,
      metrics.activeDefenseVersion
    ];
    
    await this.runQuery(sql, params);
  }

  async getMetrics(timeRange: TimeRange): Promise<SecurityMetrics[]> {
    const sql = `SELECT * FROM security_metrics 
                 WHERE timestamp >= ? AND timestamp <= ? 
                 ORDER BY timestamp DESC`;
    const params = [timeRange.start.toISOString(), timeRange.end.toISOString()];
    
    const rows = await this.getQuery(sql, params);
    return rows.map(row => ({
      timestamp: new Date(row.timestamp),
      period: row.period,
      metrics: JSON.parse(row.metrics),
      trustScore: row.trust_score,
      activeDefenseVersion: row.defense_version
    }));
  }

  async getLatestMetrics(): Promise<SecurityMetrics | null> {
    const sql = 'SELECT * FROM security_metrics ORDER BY timestamp DESC LIMIT 1';
    const rows = await this.getQuery(sql);
    
    if (rows.length === 0) return null;
    
    const row = rows[0];
    return {
      timestamp: new Date(row.timestamp),
      period: row.period,
      metrics: JSON.parse(row.metrics),
      trustScore: row.trust_score,
      activeDefenseVersion: row.defense_version
    };
  }

  // AttackDatasetRepository implementation
  async saveDataset(dataset: AttackDataset): Promise<void> {
    const sql = `INSERT OR REPLACE INTO attack_datasets 
                 (id, version, name, description, attacks, metadata, statistics, created_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      dataset.id,
      dataset.version,
      dataset.name,
      dataset.description,
      JSON.stringify(dataset.attacks),
      JSON.stringify(dataset.metadata),
      JSON.stringify(dataset.statistics),
      new Date().toISOString()
    ];
    
    await this.runQuery(sql, params);
  }

  async getDataset(id: string, version?: string): Promise<AttackDataset | null> {
    let sql = 'SELECT * FROM attack_datasets WHERE id = ?';
    const params = [id];
    
    if (version) {
      sql += ' AND version = ?';
      params.push(version);
    } else {
      sql += ' ORDER BY created_at DESC LIMIT 1';
    }
    
    const rows = await this.getQuery(sql, params);
    if (rows.length === 0) return null;
    
    const row = rows[0];
    const attacks = JSON.parse(row.attacks);
    const metadata = JSON.parse(row.metadata);
    const statistics = JSON.parse(row.statistics);

    // Convert date strings back to Date objects
    const convertedAttacks = attacks.map((attack: any) => ({
      ...attack,
      metadata: {
        ...attack.metadata,
        createdAt: new Date(attack.metadata.createdAt)
      }
    }));

    return {
      id: row.id,
      version: row.version,
      name: row.name,
      description: row.description,
      attacks: convertedAttacks,
      metadata: {
        ...metadata,
        createdAt: new Date(metadata.createdAt)
      },
      statistics
    };
  }

  async listDatasets(): Promise<AttackDataset[]> {
    const sql = 'SELECT * FROM attack_datasets ORDER BY created_at DESC';
    const rows = await this.getQuery(sql);
    
    return rows.map(row => {
      const attacks = JSON.parse(row.attacks);
      const metadata = JSON.parse(row.metadata);
      const statistics = JSON.parse(row.statistics);

      // Convert date strings back to Date objects
      const convertedAttacks = attacks.map((attack: any) => ({
        ...attack,
        metadata: {
          ...attack.metadata,
          createdAt: new Date(attack.metadata.createdAt)
        }
      }));

      return {
        id: row.id,
        version: row.version,
        name: row.name,
        description: row.description,
        attacks: convertedAttacks,
        metadata: {
          ...metadata,
          createdAt: new Date(metadata.createdAt)
        },
        statistics
      };
    });
  }

  async deleteDataset(id: string, version?: string): Promise<void> {
    let sql = 'DELETE FROM attack_datasets WHERE id = ?';
    const params = [id];
    
    if (version) {
      sql += ' AND version = ?';
      params.push(version);
    }
    
    await this.runQuery(sql, params);
  }

  // Benchmark repository methods
  async saveBenchmarkConfiguration(config: BenchmarkConfiguration): Promise<void> {
    const sql = `INSERT OR REPLACE INTO benchmark_configurations 
                 (id, name, description, attack_dataset_id, attack_dataset_version, baseline_types, test_conditions, created_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      config.id,
      config.name,
      config.description,
      config.attackDatasetId,
      config.attackDatasetVersion,
      JSON.stringify(config.baselineTypes),
      JSON.stringify(config.testConditions),
      config.createdAt.toISOString()
    ];
    
    await this.runQuery(sql, params);
  }

  async getBenchmarkConfiguration(id: string): Promise<BenchmarkConfiguration | null> {
    const sql = 'SELECT * FROM benchmark_configurations WHERE id = ?';
    const rows = await this.getQuery(sql, [id]);
    
    if (rows.length === 0) return null;
    
    const row = rows[0];
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      attackDatasetId: row.attack_dataset_id,
      attackDatasetVersion: row.attack_dataset_version,
      baselineTypes: JSON.parse(row.baseline_types),
      testConditions: JSON.parse(row.test_conditions),
      createdAt: new Date(row.created_at)
    };
  }

  async listBenchmarkConfigurations(): Promise<BenchmarkConfiguration[]> {
    const sql = 'SELECT * FROM benchmark_configurations ORDER BY created_at DESC';
    const rows = await this.getQuery(sql);
    
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      attackDatasetId: row.attack_dataset_id,
      attackDatasetVersion: row.attack_dataset_version,
      baselineTypes: JSON.parse(row.baseline_types),
      testConditions: JSON.parse(row.test_conditions),
      createdAt: new Date(row.created_at)
    }));
  }

  async saveBenchmarkResult(result: BenchmarkResult): Promise<void> {
    const sql = `INSERT OR REPLACE INTO benchmark_results 
                 (id, configuration_id, executed_at, completed_at, status, baseline_results, summary, reproducibility_hash) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [
      result.id,
      result.configurationId,
      result.executedAt.toISOString(),
      result.completedAt.toISOString(),
      result.status,
      JSON.stringify(result.baselineResults),
      JSON.stringify(result.summary),
      result.reproducibilityHash
    ];
    
    await this.runQuery(sql, params);
  }

  async getBenchmarkResult(id: string): Promise<BenchmarkResult | null> {
    const sql = 'SELECT * FROM benchmark_results WHERE id = ?';
    const rows = await this.getQuery(sql, [id]);
    
    if (rows.length === 0) return null;
    
    const row = rows[0];
    return {
      id: row.id,
      configurationId: row.configuration_id,
      executedAt: new Date(row.executed_at),
      completedAt: new Date(row.completed_at),
      status: row.status,
      baselineResults: JSON.parse(row.baseline_results),
      summary: JSON.parse(row.summary),
      reproducibilityHash: row.reproducibility_hash
    };
  }

  async listBenchmarkResults(configId?: string): Promise<BenchmarkResult[]> {
    let sql = 'SELECT * FROM benchmark_results';
    const params: any[] = [];
    
    if (configId) {
      sql += ' WHERE configuration_id = ?';
      params.push(configId);
    }
    
    sql += ' ORDER BY executed_at DESC';
    const rows = await this.getQuery(sql, params);
    
    return rows.map(row => ({
      id: row.id,
      configurationId: row.configuration_id,
      executedAt: new Date(row.executed_at),
      completedAt: new Date(row.completed_at),
      status: row.status,
      baselineResults: JSON.parse(row.baseline_results),
      summary: JSON.parse(row.summary),
      reproducibilityHash: row.reproducibility_hash
    }));
  }
}