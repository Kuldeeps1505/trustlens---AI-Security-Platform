/**
 * Web Dashboard Implementation
 * Bridges the SOCDashboard class with web interface
 */

import express from 'express';
import { SOCDashboard } from './dashboard';
import { SecurityLogExplorer } from './log-explorer';
import { JudgeModeInterface } from './judge-mode';
import { SQLiteDatabase } from '../data/database';

export class WebDashboardController {
  private socDashboard: SOCDashboard;
  private logExplorer: SecurityLogExplorer;
  private judgeMode: JudgeModeInterface;
  private database: SQLiteDatabase;

  constructor(database: SQLiteDatabase) {
    this.database = database;
    this.socDashboard = new SOCDashboard();
    this.logExplorer = new SecurityLogExplorer();
    this.judgeMode = new JudgeModeInterface();
  }

  async initialize(): Promise<void> {
    await this.socDashboard.loadDashboardData();
    await this.socDashboard.startLiveMode();
  }

  // API endpoints for the web interface
  async getDashboardData(req: express.Request, res: express.Response): Promise<void> {
    try {
      const data = await this.socDashboard.loadDashboardData();
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  async getAttackEvolution(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { attackId } = req.params;
      const tree = await this.socDashboard.generateAttackEvolutionTree(attackId || 'default');
      const stats = await this.socDashboard.generateAttackEvolutionStats(attackId || 'default');
      const formattedTree = this.socDashboard.formatAttackLineage(tree);
      const successfulPaths = this.socDashboard.highlightSuccessfulPaths(tree);

      res.json({
        tree,
        stats,
        formattedTree,
        successfulPaths
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  async getLogExplorerData(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { page = 1, pageSize = 50, filter } = req.query;
      
      // Load recent logs
      const recentLogs = await this.getRecentAuditLogs();
      await this.logExplorer.loadLogs(recentLogs);
      
      const result = await this.logExplorer.filterLogs(
        filter ? JSON.parse(filter as string) : {},
        parseInt(page as string),
        parseInt(pageSize as string)
      );
      
      const stats = await this.logExplorer.generateLogStatistics();
      
      res.json({
        ...result,
        statistics: stats
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  async searchLogs(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { query, page = 1, pageSize = 50 } = req.body;
      
      const recentLogs = await this.getRecentAuditLogs();
      await this.logExplorer.loadLogs(recentLogs);
      
      const result = await this.logExplorer.searchLogs(
        query,
        undefined,
        parseInt(page as string),
        parseInt(pageSize as string)
      );
      
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  async exportLogs(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { format, options } = req.body;
      
      const recentLogs = await this.getRecentAuditLogs();
      const exportData = await this.logExplorer.exportLogs(recentLogs, {
        format,
        ...options
      });
      
      const contentTypes = {
        'json': 'application/json',
        'csv': 'text/csv',
        'siem': 'text/plain'
      };
      
      res.setHeader('Content-Type', contentTypes[format as keyof typeof contentTypes] || 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename="trustlens-logs.${format}"`);
      res.send(exportData);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  async getJudgeModeData(req: express.Request, res: express.Response): Promise<void> {
    try {
      const data = await this.judgeMode.getJudgeModeData();
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  async submitJudgment(req: express.Request, res: express.Response): Promise<void> {
    try {
      const { attackId, judgment, reasoning } = req.body;
      await this.judgeMode.submitJudgment(attackId, judgment, reasoning);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  }

  // Render the dashboard HTML with server-side data
  async renderDashboard(req: express.Request, res: express.Response): Promise<void> {
    try {
      const dashboardData = await this.socDashboard.loadDashboardData();
      const html = this.generateDashboardHTML(dashboardData);
      res.send(html);
    } catch (error) {
      res.status(500).send(`Error loading dashboard: ${error}`);
    }
  }

  private async getRecentAuditLogs() {
    // Get recent audit logs from database
    try {
      const query = `
        SELECT * FROM audit_logs 
        ORDER BY timestamp DESC 
        LIMIT 1000
      `;
      const rows = await this.database.executeQuery(query);
      
      return rows.map(row => ({
        id: row.id,
        timestamp: new Date(row.timestamp),
        eventType: row.event_type,
        userId: row.user_id,
        sessionId: row.session_id,
        data: JSON.parse(row.data || '{}'),
        metadata: JSON.parse(row.metadata || '{}')
      }));
    } catch (error) {
      console.warn('Could not load audit logs:', error);
      return [];
    }
  }

  private generateDashboardHTML(data: any): string {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustLens SOC Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Consolas', 'Monaco', monospace; 
            background: #0a0a0a; 
            color: #00ff41; 
            min-height: 100vh; 
        }
        .header { 
            background: #1a1a1a; 
            padding: 1rem 2rem; 
            border-bottom: 2px solid #00ff41; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        .title { font-size: 1.8rem; font-weight: bold; }
        .status { display: flex; gap: 2rem; font-size: 0.9rem; }
        .indicator { 
            width: 8px; height: 8px; border-radius: 50%; 
            background: #00ff41; margin-right: 0.5rem; 
            animation: pulse 2s infinite; 
        }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .grid { 
            display: grid; 
            grid-template-columns: 1fr 1fr 1fr; 
            gap: 1rem; 
            padding: 1rem; 
            height: calc(100vh - 80px); 
        }
        .panel { 
            background: #1a1a1a; 
            border: 1px solid #00ff41; 
            padding: 1rem; 
            overflow-y: auto; 
        }
        .panel-header { 
            color: #00ff41; 
            font-weight: bold; 
            margin-bottom: 1rem; 
            padding-bottom: 0.5rem; 
            border-bottom: 1px solid #333; 
        }
        .metric { 
            display: flex; 
            justify-content: space-between; 
            margin-bottom: 0.5rem; 
            padding: 0.25rem 0; 
        }
        .value { color: #ffff00; font-weight: bold; }
        .critical { color: #ff4444; }
        .warning { color: #ffaa00; }
        .success { color: #00ff41; }
        .log-entry { 
            margin-bottom: 0.5rem; 
            padding: 0.5rem; 
            background: #0f0f0f; 
            border-left: 3px solid #333; 
        }
        .blocked { border-left-color: #ff4444; }
        .flagged { border-left-color: #ffaa00; }
        .allowed { border-left-color: #00ff41; }
        .timestamp { color: #888; font-size: 0.8rem; }
        .attack-type { color: #ff6666; font-weight: bold; }
        .evolution { font-family: monospace; white-space: pre; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="header">
        <div class="title">TRUSTLENS SOC DASHBOARD</div>
        <div class="status">
            <div><span class="indicator"></span>FIREWALL: ACTIVE</div>
            <div><span class="indicator"></span>RED TEAM: RUNNING</div>
            <div><span class="indicator"></span>AUDIT: ENABLED</div>
            <div id="time">${new Date().toLocaleTimeString()}</div>
        </div>
    </div>
    
    <div class="grid">
        <div class="panel">
            <div class="panel-header">TRUST SCORE METRICS</div>
            <div class="metric">
                <span>Overall Score:</span>
                <span class="value">${data.trustScore?.overall || 0}%</span>
            </div>
            <div class="metric">
                <span>Block Rate:</span>
                <span class="value">${data.trustScore?.components?.blockRate || 0}%</span>
            </div>
            <div class="metric">
                <span>False Positive Rate:</span>
                <span class="value">${data.trustScore?.components?.falsePositiveRate || 0}%</span>
            </div>
            <div class="metric">
                <span>Bypass Rate:</span>
                <span class="value critical">${data.trustScore?.components?.bypassRate || 0}%</span>
            </div>
            <div class="metric">
                <span>Trend:</span>
                <span class="value">${data.trustScore?.trend || 'STABLE'}</span>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header">RED TEAM PRESSURE</div>
            <div class="metric">
                <span>Current Pressure:</span>
                <span class="value">${data.redTeamPressure?.currentPressure || 0}%</span>
            </div>
            <div class="metric">
                <span>Active Attacks:</span>
                <span class="value">${data.redTeamPressure?.activeAttacks || 0}</span>
            </div>
            <div class="metric">
                <span>Successful Bypasses:</span>
                <span class="value critical">${data.redTeamPressure?.successfulBypasses || 0}</span>
            </div>
            <div class="metric">
                <span>Trend:</span>
                <span class="value">${data.redTeamPressure?.trend || 'STABLE'}</span>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header">SECURITY METRICS</div>
            <div class="metric">
                <span>Total Requests:</span>
                <span class="value">${data.securityMetrics?.metrics?.totalRequests || 0}</span>
            </div>
            <div class="metric">
                <span>Blocked:</span>
                <span class="value critical">${data.securityMetrics?.metrics?.blockedRequests || 0}</span>
            </div>
            <div class="metric">
                <span>Flagged:</span>
                <span class="value warning">${data.securityMetrics?.metrics?.flaggedRequests || 0}</span>
            </div>
            <div class="metric">
                <span>Avg Risk Score:</span>
                <span class="value">${data.securityMetrics?.metrics?.averageRiskScore || 0}%</span>
            </div>
            <div class="metric">
                <span>Processing Latency:</span>
                <span class="value">${data.securityMetrics?.metrics?.processingLatency || 0}ms</span>
            </div>
        </div>
        
        <div class="panel" style="grid-column: 1 / 4;">
            <div class="panel-header">LIVE ATTACK FEED</div>
            ${this.generateAttackFeedHTML(data.liveAttackFeed || [])}
        </div>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        setTimeout(() => location.reload(), 30000);
        
        // Update time every second
        setInterval(() => {
            document.getElementById('time').textContent = new Date().toLocaleTimeString();
        }, 1000);
    </script>
</body>
</html>`;
  }

  private generateAttackFeedHTML(attackFeed: any[]): string {
    if (!attackFeed || attackFeed.length === 0) {
      return '<div class="log-entry">No recent attacks detected</div>';
    }

    return attackFeed.map(attack => {
      const decision = attack.data?.decision?.decision?.toLowerCase() || 'unknown';
      const className = decision === 'block' ? 'blocked' : decision === 'flag' ? 'flagged' : 'allowed';
      
      return `
        <div class="log-entry ${className}">
          <div class="timestamp">[${new Date(attack.timestamp).toLocaleTimeString()}]</div>
          <div class="attack-type">${attack.data?.decision?.attackCategory?.type || attack.eventType}</div>
          <div>Decision: <span class="${decision === 'block' ? 'critical' : decision === 'flag' ? 'warning' : 'success'}">${attack.data?.decision?.decision || 'N/A'}</span></div>
          <div>Risk Score: <span class="value">${attack.data?.decision?.riskScore || 0}%</span></div>
          ${attack.data?.decision?.explanation ? `<div>Reason: ${attack.data.decision.explanation}</div>` : ''}
        </div>
      `;
    }).join('');
  }

  async shutdown(): Promise<void> {
    await this.socDashboard.stopLiveMode();
  }
}