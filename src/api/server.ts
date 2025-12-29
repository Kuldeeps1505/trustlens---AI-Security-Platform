/**
 * REST API Server for TrustLens Dataset Management
 * Provides HTTP endpoints for dataset versioning and access
 * Requirements: 3.3, 3.4, 3.5
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import { DatasetAPI, DatasetExportOptions } from './dataset';
import { AttackDatasetManager } from '../data/attack-dataset';
import { SQLiteDatabase } from '../data/database';
import { Attack, AttackMetadata } from '../types/core';
import { FirewallService } from './firewall';
import { TrustScoreEngine } from '../engines/trust-score';
import { RedTeamEngine } from '../engines/red-team';
import { WebDashboardController } from '../ui/web-dashboard';
import { SimpleWebDashboard } from '../ui/simple-web-dashboard';

export class DatasetAPIServer {
  private app: express.Application;
  private datasetAPI: DatasetAPI;
  private database: SQLiteDatabase;
  private port: number;
  private firewall: FirewallService;
  private webDashboard: SimpleWebDashboard;
  private trustScore: TrustScoreEngine;
  private redTeam: RedTeamEngine;

  constructor(port: number = 3000) {
    this.app = express();
    this.port = port;
    this.database = new SQLiteDatabase();
    this.datasetAPI = new DatasetAPI(this.database);
    this.firewall = new FirewallService();
    this.webDashboard = new SimpleWebDashboard(this.database);
    this.trustScore = new TrustScoreEngine();
    this.redTeam = new RedTeamEngine();
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware(): void {
    this.app.use(cors());
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true }));
    
    // Serve static files from public directory
    this.app.use(express.static(path.join(__dirname, '../../public')));
    
    // Request logging
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
      next();
    });
  }

  private setupRoutes(): void {
    // Serve the main web interface
    this.app.get('/', (req, res) => {
      res.sendFile(path.join(__dirname, '../../public/index.html'));
    });

    // Serve the SOC dashboard using the proper dashboard implementation
    this.app.get('/dashboard', this.webDashboard.renderDashboard.bind(this.webDashboard));

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // Dashboard API endpoints - use the simple web dashboard
    this.app.get('/api/dashboard/data', this.webDashboard.getDashboardData.bind(this.webDashboard));

    // Firewall API endpoints
    this.app.post('/api/firewall/analyze', this.analyzePrompt.bind(this));
    this.app.get('/api/firewall/stats', this.getFirewallStats.bind(this));

    // Trust Score API endpoints
    this.app.post('/api/trust/calculate', this.calculateTrustScore.bind(this));
    this.app.get('/api/trust/score/:userId', this.getTrustScore.bind(this));

    // Red Team API endpoints
    this.app.post('/api/redteam/run', this.runRedTeamTest.bind(this));
    this.app.get('/api/redteam/results', this.getRedTeamResults.bind(this));

    // Dataset versioning endpoints
    this.app.get('/api/datasets/:id/versions', this.getVersionHistory.bind(this));
    this.app.post('/api/datasets/:id/versions', this.createVersion.bind(this));
    this.app.get('/api/datasets/:id/versions/:version1/compare/:version2', this.compareVersions.bind(this));
    this.app.post('/api/datasets/:id/rollback/:version', this.rollbackToVersion.bind(this));

    // Dataset access endpoints
    this.app.get('/api/datasets', this.listDatasets.bind(this));
    this.app.get('/api/datasets/:id', this.getDataset.bind(this));
    this.app.post('/api/datasets', this.createDataset.bind(this));
    this.app.delete('/api/datasets/:id', this.deleteDataset.bind(this));

    // Dataset export endpoints
    this.app.post('/api/datasets/:id/export', this.exportDataset.bind(this));
    this.app.get('/api/datasets/:id/stats', this.getDatasetStats.bind(this));

    // Attack search endpoint
    this.app.post('/api/attacks/search', this.searchAttacks.bind(this));

    // Error handling
    this.app.use(this.errorHandler.bind(this));
  }

  // Firewall endpoints

  private async analyzePrompt(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { prompt } = req.body;
      
      if (!prompt) {
        res.status(400).json({ error: 'Prompt is required' });
        return;
      }

      const result = await this.firewall.analyzePrompt(prompt);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  private async getFirewallStats(req: express.Request, res: express.Response): Promise<void> {
    try {
      const stats = await this.firewall.getStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  // Trust Score endpoints

  private async calculateTrustScore(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { userId, interactions } = req.body;
      
      if (!userId) {
        res.status(400).json({ error: 'User ID is required' });
        return;
      }

      const score = await this.trustScore.calculateTrustScore(userId, interactions || []);
      res.json({ userId, trustScore: score });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  private async getTrustScore(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { userId } = req.params;
      const score = await this.trustScore.getTrustScore(userId);
      res.json({ userId, trustScore: score });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  // Red Team endpoints

  private async runRedTeamTest(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { target, testType } = req.body;
      const results = await this.redTeam.runAttackSimulation(target || 'default', testType || 'comprehensive');
      res.json(results);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  private async getRedTeamResults(req: express.Request, res: express.Response): Promise<void> {
    try {
      const results = await this.redTeam.getTestResults();
      res.json(results);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  // Version management endpoints

  private async getVersionHistory(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id } = req.params;
      const history = await this.datasetAPI.getVersionHistory(id);
      res.json(history);
    } catch (error) {
      res.status(404).json({ error: (error as Error).message });
    }
  }

  private async createVersion(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id } = req.params;
      const changes = req.body;
      const newDataset = await this.datasetAPI.createVersion(id, changes);
      res.status(201).json(newDataset);
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
    }
  }

  private async compareVersions(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id, version1, version2 } = req.params;
      const comparison = await this.datasetAPI.compareVersions(id, version1, version2);
      res.json(comparison);
    } catch (error) {
      res.status(404).json({ error: (error as Error).message });
    }
  }

  private async rollbackToVersion(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id, version } = req.params;
      const rolledBackDataset = await this.datasetAPI.rollbackToVersion(id, version);
      res.json(rolledBackDataset);
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
    }
  }

  // Dataset access endpoints

  private async listDatasets(req: express.Request, res: express.Response): Promise<void> {
    try {
      const datasetManager = new AttackDatasetManager(this.database);
      const datasets = await datasetManager.listDatasets();
      res.json(datasets);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  private async getDataset(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id } = req.params;
      const { version } = req.query;
      const datasetManager = new AttackDatasetManager(this.database);
      const dataset = await datasetManager.getDataset(id, version as string);
      
      if (!dataset) {
        res.status(404).json({ error: 'Dataset not found' });
        return;
      }
      
      res.json(dataset);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  private async createDataset(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { name, description, attacks = [] } = req.body;
      
      if (!name) {
        res.status(400).json({ error: 'Dataset name is required' });
        return;
      }

      const datasetManager = new AttackDatasetManager(this.database);
      const dataset = await datasetManager.createDataset(name, description || '', attacks);
      res.status(201).json(dataset);
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
    }
  }

  private async deleteDataset(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id } = req.params;
      const { version } = req.query;
      const datasetManager = new AttackDatasetManager(this.database);
      await datasetManager.deleteDataset(id, version as string);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  // Export endpoints

  private async exportDataset(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id } = req.params;
      const options: DatasetExportOptions = req.body;

      if (!options.format) {
        res.status(400).json({ error: 'Export format is required' });
        return;
      }

      const result = await this.datasetAPI.exportDataset(id, options);
      
      // Set appropriate content type based on format
      const contentTypes = {
        'JSON': 'application/json',
        'CSV': 'text/csv',
        'STIX': 'application/json',
        'MITRE_ATT&CK': 'application/json',
        'YARA': 'text/plain'
      };

      res.setHeader('Content-Type', contentTypes[options.format] || 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="dataset-${id}-${result.metadata.version}.${options.format.toLowerCase()}"`);
      
      res.json(result);
    } catch (error) {
      res.status(400).json({ error: (error as Error).message });
    }
  }

  private async getDatasetStats(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { id } = req.params;
      const stats = await this.datasetAPI.getDatasetAccessStats(id);
      res.json(stats);
    } catch (error) {
      res.status(404).json({ error: (error as Error).message });
    }
  }

  // Search endpoint

  private async searchAttacks(req: express.Request, res: express.Response): Promise<void> {
    try {
      const query = req.body;
      const datasetManager = new AttackDatasetManager(this.database);
      const attacks = await datasetManager.searchAttacks(query);
      res.json({ attacks, count: attacks.length });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  // Error handling

  private errorHandler(error: Error, req: express.Request, res: express.Response, next: express.NextFunction): void {
    console.error('API Error:', error);
    res.status(500).json({ 
      error: 'Internal server error',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }

  // Server lifecycle

  async start(): Promise<void> {
    try {
      await this.database.connect();
      console.log('Database connected successfully');

      // Initialize the web dashboard
      await this.webDashboard.initialize();
      console.log('Web dashboard initialized');

      this.app.listen(this.port, () => {
        console.log(`TrustLens AI Security Platform running on port ${this.port}`);
        console.log(`Web Interface: http://localhost:${this.port}`);
        console.log(`Professional SOC Dashboard: http://localhost:${this.port}/dashboard`);
        console.log(`Health check: http://localhost:${this.port}/health`);
        console.log(`API documentation: http://localhost:${this.port}/api/datasets`);
      });
    } catch (error) {
      console.error('Failed to start server:', error);
      throw error;
    }
  }

  async stop(): Promise<void> {
    try {
      await this.webDashboard.shutdown();
      await this.database.disconnect();
      console.log('TrustLens server stopped');
    } catch (error) {
      console.error('Error stopping server:', error);
    }
  }
}

// Export for use in other modules
export { DatasetAPI } from './dataset';