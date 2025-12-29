/**
 * Dataset Versioning and Access API
 * Implements dataset version management with history preservation
 * Provides API endpoints for dataset access and export
 * Adds structured format export for external security tools
 * Requirements: 3.3, 3.4, 3.5
 */

import { v4 as uuidv4 } from 'uuid';
import { AttackDataset, Attack, AttackCategory, AttackMetadata } from '../types/core';
import { AttackDatasetManager, AttackSearchQuery, DatasetStatistics } from '../data/attack-dataset';
import { SQLiteDatabase } from '../data/database';

export interface DatasetVersionInfo {
  id: string;
  version: string;
  name: string;
  description: string;
  createdAt: Date;
  attackCount: number;
  parentVersion?: string;
  changesSummary: string;
}

export interface DatasetExportOptions {
  format: 'JSON' | 'CSV' | 'STIX' | 'MITRE_ATT&CK' | 'YARA';
  includeMetadata: boolean;
  filterBy?: AttackSearchQuery;
  version?: string;
}

export interface DatasetVersionHistory {
  datasetId: string;
  versions: DatasetVersionInfo[];
  totalVersions: number;
}

export interface ExportResult {
  format: string;
  data: string;
  metadata: {
    exportedAt: Date;
    recordCount: number;
    version: string;
    checksum: string;
  };
}

export class DatasetAPI {
  private datasetManager: AttackDatasetManager;
  private database: SQLiteDatabase;

  constructor(database: SQLiteDatabase) {
    this.database = database;
    this.datasetManager = new AttackDatasetManager(database);
  }

  /**
   * Get version history for a dataset
   * Requirement 3.4: Dataset versioning integrity
   */
  async getVersionHistory(datasetId: string): Promise<DatasetVersionHistory> {
    const versions = await this.database.executeQuery(
      'SELECT id, version, name, description, created_at, attacks FROM attack_datasets WHERE id = ? ORDER BY created_at ASC',
      [datasetId]
    );

    if (versions.length === 0) {
      throw new Error(`Dataset with id ${datasetId} not found`);
    }

    const versionInfos: DatasetVersionInfo[] = versions.map((row, index) => {
      const attacks = JSON.parse(row.attacks);
      const previousVersion = index > 0 ? versions[index - 1] : null;
      const previousAttacks = previousVersion ? JSON.parse(previousVersion.attacks) : [];
      
      return {
        id: row.id,
        version: row.version,
        name: row.name,
        description: row.description,
        createdAt: new Date(row.created_at),
        attackCount: attacks.length,
        parentVersion: previousVersion ? previousVersion.version : undefined,
        changesSummary: this.generateChangesSummary(previousAttacks, attacks)
      };
    });

    return {
      datasetId,
      versions: versionInfos,
      totalVersions: versions.length
    };
  }

  /**
   * Create a new version of an existing dataset
   * Requirement 3.4: Dataset versioning integrity
   */
  async createVersion(datasetId: string, changes: {
    name?: string;
    description?: string;
    addAttacks?: Attack[];
    removeAttackIds?: string[];
    updateAttacks?: { id: string; metadata: Partial<AttackMetadata> }[];
  }): Promise<AttackDataset> {
    const currentDataset = await this.datasetManager.getDataset(datasetId);
    if (!currentDataset) {
      throw new Error(`Dataset with id ${datasetId} not found`);
    }

    // Start with current attacks
    let updatedAttacks = [...currentDataset.attacks];

    // Apply removals
    if (changes.removeAttackIds) {
      updatedAttacks = updatedAttacks.filter(attack => 
        !changes.removeAttackIds!.includes(attack.id)
      );
    }

    // Apply updates
    if (changes.updateAttacks) {
      for (const update of changes.updateAttacks) {
        const attackIndex = updatedAttacks.findIndex(attack => attack.id === update.id);
        if (attackIndex !== -1) {
          updatedAttacks[attackIndex] = {
            ...updatedAttacks[attackIndex],
            metadata: {
              ...updatedAttacks[attackIndex].metadata,
              ...update.metadata
            }
          };
        }
      }
    }

    // Apply additions
    if (changes.addAttacks) {
      updatedAttacks.push(...changes.addAttacks);
    }

    // Create new version
    const newVersion = this.incrementVersion(currentDataset.version);
    const statistics = this.calculateStatistics(updatedAttacks);

    const newDataset: AttackDataset = {
      ...currentDataset,
      version: newVersion,
      name: changes.name || currentDataset.name,
      description: changes.description || currentDataset.description,
      attacks: updatedAttacks,
      statistics,
      metadata: {
        ...currentDataset.metadata,
        createdAt: new Date()
      }
    };

    await this.database.saveDataset(newDataset);
    return newDataset;
  }

  /**
   * Export dataset in various formats for external security tools
   * Requirement 3.5: Export format compliance
   */
  async exportDataset(datasetId: string, options: DatasetExportOptions): Promise<ExportResult> {
    const dataset = await this.datasetManager.getDataset(datasetId, options.version);
    if (!dataset) {
      throw new Error(`Dataset with id ${datasetId} not found`);
    }

    // Apply filters if specified
    let attacks = dataset.attacks;
    if (options.filterBy) {
      attacks = await this.filterAttacks(attacks, options.filterBy);
    }

    let exportData: string;
    switch (options.format) {
      case 'JSON':
        exportData = this.exportAsJSON(dataset, attacks, options.includeMetadata);
        break;
      case 'CSV':
        exportData = this.exportAsCSV(attacks, options.includeMetadata);
        break;
      case 'STIX':
        exportData = this.exportAsSTIX(dataset, attacks);
        break;
      case 'MITRE_ATT&CK':
        exportData = this.exportAsMITRE(attacks);
        break;
      case 'YARA':
        exportData = this.exportAsYARA(attacks);
        break;
      default:
        throw new Error(`Unsupported export format: ${options.format}`);
    }

    const checksum = this.calculateChecksum(exportData);

    return {
      format: options.format,
      data: exportData,
      metadata: {
        exportedAt: new Date(),
        recordCount: attacks.length,
        version: dataset.version,
        checksum
      }
    };
  }

  /**
   * Get dataset access statistics and usage metrics
   * Requirement 3.3: Dataset access APIs
   */
  async getDatasetAccessStats(datasetId: string): Promise<{
    totalAccesses: number;
    lastAccessed: Date;
    popularVersions: { version: string; accessCount: number }[];
    exportHistory: { format: string; exportedAt: Date; recordCount: number }[];
  }> {
    // This would typically be tracked in a separate access log table
    // For now, return mock data structure
    return {
      totalAccesses: 0,
      lastAccessed: new Date(),
      popularVersions: [],
      exportHistory: []
    };
  }

  /**
   * Compare two dataset versions
   * Requirement 3.4: Dataset versioning integrity
   */
  async compareVersions(datasetId: string, version1: string, version2: string): Promise<{
    added: Attack[];
    removed: Attack[];
    modified: { attack: Attack; changes: string[] }[];
    summary: string;
  }> {
    const dataset1 = await this.datasetManager.getDataset(datasetId, version1);
    const dataset2 = await this.datasetManager.getDataset(datasetId, version2);

    if (!dataset1 || !dataset2) {
      throw new Error('One or both dataset versions not found');
    }

    const attacks1Map = new Map(dataset1.attacks.map(attack => [attack.id, attack]));
    const attacks2Map = new Map(dataset2.attacks.map(attack => [attack.id, attack]));

    const added: Attack[] = [];
    const removed: Attack[] = [];
    const modified: { attack: Attack; changes: string[] }[] = [];

    // Find added attacks
    for (const [id, attack] of attacks2Map) {
      if (!attacks1Map.has(id)) {
        added.push(attack);
      }
    }

    // Find removed and modified attacks
    for (const [id, attack1] of attacks1Map) {
      if (!attacks2Map.has(id)) {
        removed.push(attack1);
      } else {
        const attack2 = attacks2Map.get(id)!;
        const changes = this.detectAttackChanges(attack1, attack2);
        if (changes.length > 0) {
          modified.push({ attack: attack2, changes });
        }
      }
    }

    const summary = `Added: ${added.length}, Removed: ${removed.length}, Modified: ${modified.length}`;

    return { added, removed, modified, summary };
  }

  /**
   * Rollback to a previous dataset version
   * Requirement 3.4: Dataset versioning integrity
   */
  async rollbackToVersion(datasetId: string, targetVersion: string): Promise<AttackDataset> {
    const targetDataset = await this.datasetManager.getDataset(datasetId, targetVersion);
    if (!targetDataset) {
      throw new Error(`Target version ${targetVersion} not found`);
    }

    // Create a new version based on the target version
    const newVersion = this.incrementVersion(targetDataset.version);
    const rolledBackDataset: AttackDataset = {
      ...targetDataset,
      version: newVersion,
      metadata: {
        ...targetDataset.metadata,
        createdAt: new Date()
      }
    };

    await this.database.saveDataset(rolledBackDataset);
    return rolledBackDataset;
  }

  // Private helper methods

  private generateChangesSummary(previousAttacks: Attack[], currentAttacks: Attack[]): string {
    const prevIds = new Set(previousAttacks.map(a => a.id));
    const currIds = new Set(currentAttacks.map(a => a.id));

    const added = currentAttacks.filter(a => !prevIds.has(a.id)).length;
    const removed = previousAttacks.filter(a => !currIds.has(a.id)).length;
    const modified = currentAttacks.filter(a => {
      if (!prevIds.has(a.id)) return false;
      const prev = previousAttacks.find(p => p.id === a.id);
      return prev && JSON.stringify(prev) !== JSON.stringify(a);
    }).length;

    if (added === 0 && removed === 0 && modified === 0) {
      return 'No changes';
    }

    const parts = [];
    if (added > 0) parts.push(`+${added} attacks`);
    if (removed > 0) parts.push(`-${removed} attacks`);
    if (modified > 0) parts.push(`~${modified} modified`);

    return parts.join(', ');
  }

  private incrementVersion(version: string): string {
    const parts = version.split('.');
    const patch = parseInt(parts[2] || '0') + 1;
    return `${parts[0]}.${parts[1]}.${patch}`;
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

  private async filterAttacks(attacks: Attack[], query: AttackSearchQuery): Promise<Attack[]> {
    return attacks.filter(attack => {
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

  private exportAsJSON(dataset: AttackDataset, attacks: Attack[], includeMetadata: boolean): string {
    const exportData = {
      dataset: {
        id: dataset.id,
        version: dataset.version,
        name: dataset.name,
        description: dataset.description,
        ...(includeMetadata && { metadata: dataset.metadata, statistics: dataset.statistics })
      },
      attacks: attacks.map(attack => ({
        id: attack.id,
        prompt: attack.prompt,
        category: attack.category,
        generation: attack.generation,
        ...(attack.parentId && { parentId: attack.parentId }),
        ...(includeMetadata && { metadata: attack.metadata })
      }))
    };

    return JSON.stringify(exportData, null, 2);
  }

  private exportAsCSV(attacks: Attack[], includeMetadata: boolean): string {
    const headers = ['id', 'prompt', 'category_type', 'category_confidence', 'generation'];
    if (includeMetadata) {
      headers.push('created_at', 'source', 'severity', 'success_rate', 'average_risk_score');
    }

    const rows = attacks.map(attack => {
      const row = [
        attack.id,
        `"${attack.prompt.replace(/"/g, '""')}"`,
        attack.category.type,
        attack.category.confidence.toString(),
        attack.generation.toString()
      ];

      if (includeMetadata) {
        row.push(
          attack.metadata.createdAt.toISOString(),
          attack.metadata.source,
          attack.metadata.severity,
          (attack.metadata.successRate || 0).toString(),
          (attack.metadata.averageRiskScore || 0).toString()
        );
      }

      return row.join(',');
    });

    return [headers.join(','), ...rows].join('\n');
  }

  private exportAsSTIX(dataset: AttackDataset, attacks: Attack[]): string {
    // STIX 2.1 format for threat intelligence sharing
    const stixBundle = {
      type: 'bundle',
      id: `bundle--${uuidv4()}`,
      objects: [
        {
          type: 'malware',
          spec_version: '2.1',
          id: `malware--${dataset.id}`,
          created: dataset.metadata.createdAt.toISOString(),
          modified: dataset.metadata.createdAt.toISOString(),
          name: dataset.name,
          description: dataset.description,
          malware_types: ['trojan'],
          is_family: false
        },
        ...attacks.map(attack => ({
          type: 'attack-pattern',
          spec_version: '2.1',
          id: `attack-pattern--${attack.id}`,
          created: attack.metadata.createdAt.toISOString(),
          modified: attack.metadata.createdAt.toISOString(),
          name: `${attack.category.type} Attack`,
          description: attack.prompt,
          kill_chain_phases: [{
            kill_chain_name: 'mitre-attack',
            phase_name: this.mapCategoryToMITREPhase(attack.category.type)
          }]
        }))
      ]
    };

    return JSON.stringify(stixBundle, null, 2);
  }

  private exportAsMITRE(attacks: Attack[]): string {
    // MITRE ATT&CK framework format
    const mitreData = {
      name: 'TrustLens Attack Dataset',
      version: '1.0',
      domain: 'enterprise-attack',
      techniques: attacks.map(attack => ({
        techniqueID: this.mapCategoryToMITRETechnique(attack.category.type),
        techniqueName: `${attack.category.type} Attack`,
        comment: attack.prompt,
        enabled: true,
        metadata: {
          severity: attack.metadata.severity,
          source: attack.metadata.source,
          successRate: attack.metadata.successRate
        }
      }))
    };

    return JSON.stringify(mitreData, null, 2);
  }

  private exportAsYARA(attacks: Attack[]): string {
    // YARA rules for attack pattern detection
    const yaraRules = attacks.map((attack, index) => {
      const ruleName = `trustlens_attack_${index + 1}`;
      const keywords = this.extractKeywords(attack.prompt);
      
      return `rule ${ruleName} {
    meta:
        description = "${attack.category.type} attack pattern"
        severity = "${attack.metadata.severity}"
        source = "TrustLens"
        attack_id = "${attack.id}"
    
    strings:
${keywords.map(keyword => `        $keyword${keywords.indexOf(keyword)} = "${keyword}" nocase`).join('\n')}
    
    condition:
        any of ($keyword*)
}`;
    }).join('\n\n');

    return yaraRules;
  }

  private mapCategoryToMITREPhase(category: AttackCategory['type']): string {
    const mapping = {
      'PROMPT_INJECTION': 'initial-access',
      'JAILBREAK': 'defense-evasion',
      'INSTRUCTION_OVERRIDE': 'execution',
      'ROLE_MANIPULATION': 'privilege-escalation'
    };
    return mapping[category] || 'execution';
  }

  private mapCategoryToMITRETechnique(category: AttackCategory['type']): string {
    const mapping = {
      'PROMPT_INJECTION': 'T1566',
      'JAILBREAK': 'T1055',
      'INSTRUCTION_OVERRIDE': 'T1059',
      'ROLE_MANIPULATION': 'T1134'
    };
    return mapping[category] || 'T1059';
  }

  private extractKeywords(prompt: string): string[] {
    // Simple keyword extraction - in practice, this would be more sophisticated
    const words = prompt.toLowerCase().split(/\s+/);
    const keywords = words.filter(word => 
      word.length > 3 && 
      !['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'].includes(word)
    );
    return [...new Set(keywords)].slice(0, 10); // Limit to 10 unique keywords
  }

  private detectAttackChanges(attack1: Attack, attack2: Attack): string[] {
    const changes: string[] = [];

    if (attack1.prompt !== attack2.prompt) {
      changes.push('prompt');
    }
    if (JSON.stringify(attack1.category) !== JSON.stringify(attack2.category)) {
      changes.push('category');
    }
    if (JSON.stringify(attack1.metadata) !== JSON.stringify(attack2.metadata)) {
      changes.push('metadata');
    }
    if (attack1.generation !== attack2.generation) {
      changes.push('generation');
    }

    return changes;
  }

  private calculateChecksum(data: string): string {
    // Simple checksum calculation - in practice, use a proper hash function
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }
}