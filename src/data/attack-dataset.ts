/**
 * Attack Dataset Storage System
 * Implements versioned attack dataset schema with metadata
 * Provides CRUD operations for attack storage and retrieval
 * Handles attack categorization and severity tracking
 * Requirements: 3.1, 3.2
 */

import { v4 as uuidv4 } from 'uuid';
import { AttackDataset, Attack, AttackCategory, AttackMetadata } from '../types/core';
import { SQLiteDatabase } from './database';

export interface AttackDatasetService {
  createDataset(name: string, description: string, attacks: Attack[]): Promise<AttackDataset>;
  addAttackToDataset(datasetId: string, attack: Attack): Promise<AttackDataset>;
  removeAttackFromDataset(datasetId: string, attackId: string): Promise<AttackDataset>;
  updateAttackMetadata(datasetId: string, attackId: string, metadata: Partial<AttackMetadata>): Promise<AttackDataset>;
  getDataset(id: string, version?: string): Promise<AttackDataset | null>;
  listDatasets(): Promise<AttackDataset[]>;
  deleteDataset(id: string, version?: string): Promise<void>;
  searchAttacks(query: AttackSearchQuery): Promise<Attack[]>;
  getDatasetStatistics(id: string, version?: string): Promise<DatasetStatistics>;
}

export interface AttackSearchQuery {
  category?: AttackCategory['type'];
  severity?: AttackMetadata['severity'];
  source?: AttackMetadata['source'];
  minSuccessRate?: number;
  maxSuccessRate?: number;
  textSearch?: string;
}

export interface DatasetStatistics {
  totalAttacks: number;
  successRate: number;
  averageRiskScore: number;
  categoryDistribution: Record<string, number>;
  severityDistribution: Record<string, number>;
  sourceDistribution: Record<string, number>;
}

export class AttackDatasetManager implements AttackDatasetService {
  private database: SQLiteDatabase;

  constructor(database: SQLiteDatabase) {
    this.database = database;
  }

  async createDataset(name: string, description: string, attacks: Attack[] = []): Promise<AttackDataset> {
    const id = uuidv4();
    const version = '1.0.0';
    const now = new Date();

    // Validate attacks have complete metadata
    const validatedAttacks = attacks.map(attack => this.validateAttackMetadata(attack));

    // Calculate statistics
    const statistics = this.calculateStatistics(validatedAttacks);

    // Determine overall dataset metadata based on attacks
    const categoryDistribution = statistics.categoryDistribution;
    const mostCommonCategory = Object.keys(categoryDistribution).reduce((a, b) => 
      categoryDistribution[a] > categoryDistribution[b] ? a : b, 'PROMPT_INJECTION'
    ) as AttackCategory['type'];

    const severityDistribution = statistics.severityDistribution;
    const mostCommonSeverity = Object.keys(severityDistribution).reduce((a, b) => 
      severityDistribution[a] > severityDistribution[b] ? a : b, 'MEDIUM'
    ) as AttackMetadata['severity'];

    const dataset: AttackDataset = {
      id,
      version,
      name,
      description,
      attacks: validatedAttacks,
      metadata: {
        createdAt: now,
        source: this.determineDatasetSource(validatedAttacks),
        category: {
          type: mostCommonCategory,
          confidence: 0.8,
          indicators: []
        },
        severity: mostCommonSeverity
      },
      statistics
    };

    await this.database.saveDataset(dataset);
    return dataset;
  }

  async addAttackToDataset(datasetId: string, attack: Attack): Promise<AttackDataset> {
    const dataset = await this.database.getDataset(datasetId);
    if (!dataset) {
      throw new Error(`Dataset with id ${datasetId} not found`);
    }

    // Validate attack metadata
    const validatedAttack = this.validateAttackMetadata(attack);

    // Create new version with added attack
    const newVersion = this.incrementVersion(dataset.version);
    const updatedAttacks = [...dataset.attacks, validatedAttack];
    const updatedStatistics = this.calculateStatistics(updatedAttacks);

    const updatedDataset: AttackDataset = {
      ...dataset,
      version: newVersion,
      attacks: updatedAttacks,
      statistics: updatedStatistics,
      metadata: {
        ...dataset.metadata,
        createdAt: new Date()
      }
    };

    await this.database.saveDataset(updatedDataset);
    return updatedDataset;
  }

  async removeAttackFromDataset(datasetId: string, attackId: string): Promise<AttackDataset> {
    const dataset = await this.database.getDataset(datasetId);
    if (!dataset) {
      throw new Error(`Dataset with id ${datasetId} not found`);
    }

    const attackIndex = dataset.attacks.findIndex(attack => attack.id === attackId);
    if (attackIndex === -1) {
      throw new Error(`Attack with id ${attackId} not found in dataset`);
    }

    // Create new version with removed attack
    const newVersion = this.incrementVersion(dataset.version);
    const updatedAttacks = dataset.attacks.filter(attack => attack.id !== attackId);
    const updatedStatistics = this.calculateStatistics(updatedAttacks);

    const updatedDataset: AttackDataset = {
      ...dataset,
      version: newVersion,
      attacks: updatedAttacks,
      statistics: updatedStatistics,
      metadata: {
        ...dataset.metadata,
        createdAt: new Date()
      }
    };

    await this.database.saveDataset(updatedDataset);
    return updatedDataset;
  }

  async updateAttackMetadata(datasetId: string, attackId: string, metadata: Partial<AttackMetadata>): Promise<AttackDataset> {
    const dataset = await this.database.getDataset(datasetId);
    if (!dataset) {
      throw new Error(`Dataset with id ${datasetId} not found`);
    }

    const attackIndex = dataset.attacks.findIndex(attack => attack.id === attackId);
    if (attackIndex === -1) {
      throw new Error(`Attack with id ${attackId} not found in dataset`);
    }

    // Create new version with updated attack metadata
    const newVersion = this.incrementVersion(dataset.version);
    const updatedAttacks = [...dataset.attacks];
    updatedAttacks[attackIndex] = {
      ...updatedAttacks[attackIndex],
      metadata: {
        ...updatedAttacks[attackIndex].metadata,
        ...metadata
      }
    };

    const updatedStatistics = this.calculateStatistics(updatedAttacks);

    const updatedDataset: AttackDataset = {
      ...dataset,
      version: newVersion,
      attacks: updatedAttacks,
      statistics: updatedStatistics,
      metadata: {
        ...dataset.metadata,
        createdAt: new Date()
      }
    };

    await this.database.saveDataset(updatedDataset);
    return updatedDataset;
  }

  async getDataset(id: string, version?: string): Promise<AttackDataset | null> {
    return await this.database.getDataset(id, version);
  }

  async listDatasets(): Promise<AttackDataset[]> {
    return await this.database.listDatasets();
  }

  async deleteDataset(id: string, version?: string): Promise<void> {
    await this.database.deleteDataset(id, version);
  }

  async searchAttacks(query: AttackSearchQuery): Promise<Attack[]> {
    const datasets = await this.database.listDatasets();
    let allAttacks: Attack[] = [];

    // Collect all attacks from all datasets
    for (const dataset of datasets) {
      allAttacks = allAttacks.concat(dataset.attacks);
    }

    // Apply filters
    return allAttacks.filter(attack => {
      if (query.category && attack.category.type !== query.category) {
        return false;
      }
      if (query.severity && attack.metadata.severity !== query.severity) {
        return false;
      }
      if (query.source && attack.metadata.source !== query.source) {
        return false;
      }
      if (query.minSuccessRate !== undefined && (attack.metadata.successRate || 0) < query.minSuccessRate) {
        return false;
      }
      if (query.maxSuccessRate !== undefined && (attack.metadata.successRate || 0) > query.maxSuccessRate) {
        return false;
      }
      if (query.textSearch && !attack.prompt.toLowerCase().includes(query.textSearch.toLowerCase())) {
        return false;
      }
      return true;
    });
  }

  async getDatasetStatistics(id: string, version?: string): Promise<DatasetStatistics> {
    const dataset = await this.database.getDataset(id, version);
    if (!dataset) {
      throw new Error(`Dataset with id ${id} not found`);
    }
    return dataset.statistics;
  }

  private validateAttackMetadata(attack: Attack): Attack {
    // Ensure attack has complete metadata
    const validatedMetadata: AttackMetadata = {
      createdAt: attack.metadata.createdAt || new Date(),
      source: attack.metadata.source || 'MANUAL',
      severity: attack.metadata.severity || 'MEDIUM',
      successRate: attack.metadata.successRate || 0,
      averageRiskScore: attack.metadata.averageRiskScore || 0
    };

    return {
      ...attack,
      id: attack.id || uuidv4(),
      metadata: validatedMetadata
    };
  }

  private calculateStatistics(attacks: Attack[]): DatasetStatistics {
    if (attacks.length === 0) {
      return {
        totalAttacks: 0,
        successRate: 0,
        averageRiskScore: 0,
        categoryDistribution: {},
        severityDistribution: {},
        sourceDistribution: {}
      };
    }

    const categoryDistribution: Record<string, number> = {};
    const severityDistribution: Record<string, number> = {};
    const sourceDistribution: Record<string, number> = {};
    
    let totalSuccessRate = 0;
    let totalRiskScore = 0;
    let attacksWithSuccessRate = 0;
    let attacksWithRiskScore = 0;

    for (const attack of attacks) {
      // Category distribution
      const category = attack.category.type;
      categoryDistribution[category] = (categoryDistribution[category] || 0) + 1;

      // Severity distribution
      const severity = attack.metadata.severity;
      severityDistribution[severity] = (severityDistribution[severity] || 0) + 1;

      // Source distribution
      const source = attack.metadata.source;
      sourceDistribution[source] = (sourceDistribution[source] || 0) + 1;

      // Success rate calculation
      if (attack.metadata.successRate !== undefined) {
        totalSuccessRate += attack.metadata.successRate;
        attacksWithSuccessRate++;
      }

      // Risk score calculation
      if (attack.metadata.averageRiskScore !== undefined) {
        totalRiskScore += attack.metadata.averageRiskScore;
        attacksWithRiskScore++;
      }
    }

    return {
      totalAttacks: attacks.length,
      successRate: attacksWithSuccessRate > 0 ? totalSuccessRate / attacksWithSuccessRate : 0,
      averageRiskScore: attacksWithRiskScore > 0 ? totalRiskScore / attacksWithRiskScore : 0,
      categoryDistribution,
      severityDistribution,
      sourceDistribution
    };
  }

  private determineDatasetSource(attacks: Attack[]): AttackMetadata['source'] {
    if (attacks.length === 0) return 'MANUAL';

    const sourceCounts = attacks.reduce((acc, attack) => {
      acc[attack.metadata.source] = (acc[attack.metadata.source] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // Return the most common source
    return Object.keys(sourceCounts).reduce((a, b) => 
      sourceCounts[a] > sourceCounts[b] ? a : b
    ) as AttackMetadata['source'];
  }

  private incrementVersion(version: string): string {
    const parts = version.split('.');
    const patch = parseInt(parts[2] || '0') + 1;
    return `${parts[0]}.${parts[1]}.${patch}`;
  }
}