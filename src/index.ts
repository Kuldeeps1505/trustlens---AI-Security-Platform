/**
 * TrustLens AI Security Platform
 * Main application entry point
 */

import { FirewallService } from './api/firewall';
import { DatasetAPI } from './api/dataset';
import { RedTeamEngine } from './engines/red-team';
import { TrustScoreEngine } from './engines/trust-score';
import { SQLiteDatabase } from './data/database';
import { AttackDatasetManager } from './data/attack-dataset';
import { SOCDashboard } from './ui/dashboard';
import { JudgeModeInterface } from './ui/judge-mode';

export class TrustLensPlatform {
  private firewall: FirewallService;
  private datasetAPI: DatasetAPI;
  private datasetManager: AttackDatasetManager;
  private redTeam: RedTeamEngine;
  private trustScore: TrustScoreEngine;
  private database: SQLiteDatabase;
  private dashboard: SOCDashboard;
  private judgeMode: JudgeModeInterface;

  constructor() {
    this.firewall = new FirewallService();
    this.database = new SQLiteDatabase();
    this.datasetAPI = new DatasetAPI(this.database);
    this.datasetManager = new AttackDatasetManager(this.database);
    this.redTeam = new RedTeamEngine();
    this.trustScore = new TrustScoreEngine();
    this.dashboard = new SOCDashboard();
    this.judgeMode = new JudgeModeInterface();
  }

  async initialize(): Promise<void> {
    console.log('Initializing TrustLens AI Security Platform...');
    
    try {
      await this.database.connect();
      console.log('Database connected successfully');
      
      // Load initial dashboard data
      await this.dashboard.loadDashboardData();
      console.log('Dashboard initialized');
      
      console.log('TrustLens platform ready');
    } catch (error) {
      console.error('Failed to initialize platform:', error);
      throw error;
    }
  }

  async shutdown(): Promise<void> {
    console.log('Shutting down TrustLens platform...');
    
    try {
      await this.database.disconnect();
      console.log('Platform shutdown complete');
    } catch (error) {
      console.error('Error during shutdown:', error);
    }
  }

  // Getters for accessing platform components
  getFirewall(): FirewallService {
    return this.firewall;
  }

  getDatasetAPI(): DatasetAPI {
    return this.datasetAPI;
  }

  getDatasetManager(): AttackDatasetManager {
    return this.datasetManager;
  }

  getRedTeam(): RedTeamEngine {
    return this.redTeam;
  }

  getTrustScore(): TrustScoreEngine {
    return this.trustScore;
  }

  getDatabase(): SQLiteDatabase {
    return this.database;
  }

  getDashboard(): SOCDashboard {
    return this.dashboard;
  }

  getJudgeMode(): JudgeModeInterface {
    return this.judgeMode;
  }
}

// Export all core types and interfaces
export * from './types/core';
export * from './api/firewall';
export * from './api/dataset';
export * from './data/attack-dataset';
export * from './engines/red-team';
export * from './engines/trust-score';
export * from './data/database';
export * from './ui/dashboard';
export * from './ui/judge-mode';

// Main execution when run directly
if (require.main === module) {
  const platform = new TrustLensPlatform();
  
  platform.initialize()
    .then(() => {
      console.log('TrustLens platform is running...');
      
      // Graceful shutdown handling
      process.on('SIGINT', async () => {
        console.log('\nReceived SIGINT, shutting down gracefully...');
        await platform.shutdown();
        process.exit(0);
      });
      
      process.on('SIGTERM', async () => {
        console.log('\nReceived SIGTERM, shutting down gracefully...');
        await platform.shutdown();
        process.exit(0);
      });
    })
    .catch((error) => {
      console.error('Failed to start platform:', error);
      process.exit(1);
    });
}