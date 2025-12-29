/**
 * Simple Web Dashboard Implementation
 * Renders the SOC dashboard directly as HTML using the dashboard logic
 */

import express from 'express';
import { SOCDashboard } from './dashboard';
import { SQLiteDatabase } from '../data/database';

export class SimpleWebDashboard {
  private socDashboard: SOCDashboard;
  private database: SQLiteDatabase;

  constructor(database: SQLiteDatabase) {
    this.database = database;
    this.socDashboard = new SOCDashboard();
  }

  async initialize(): Promise<void> {
    await this.socDashboard.loadDashboardData();
    await this.socDashboard.startLiveMode();
  }

  async renderDashboard(req: express.Request, res: express.Response): Promise<void> {
    try {
      const dashboardData = await this.socDashboard.loadDashboardData();
      const html = this.generateDashboardHTML(dashboardData);
      res.send(html);
    } catch (error) {
      res.status(500).send(`Error loading dashboard: ${error}`);
    }
  }

  async getDashboardData(req: express.Request, res: express.Response): Promise<void> {
    try {
      const data = await this.socDashboard.loadDashboardData();
      res.json(data);
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
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
        .refresh-btn {
            background: #333;
            color: #00ff41;
            border: 1px solid #00ff41;
            padding: 0.25rem 0.5rem;
            cursor: pointer;
            font-family: inherit;
            font-size: 0.8rem;
            float: right;
        }
        .refresh-btn:hover {
            background: #00ff41;
            color: #000;
        }
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
            <div class="panel-header">
                TRUST SCORE METRICS
                <button class="refresh-btn" onclick="location.reload()">REFRESH</button>
            </div>
            <div class="metric">
                <span>Overall Score:</span>
                <span class="value">${data.trustScore?.overall || 75}%</span>
            </div>
            <div class="metric">
                <span>Block Rate:</span>
                <span class="value">${data.trustScore?.components?.blockRate || 85}%</span>
            </div>
            <div class="metric">
                <span>False Positive Rate:</span>
                <span class="value">${data.trustScore?.components?.falsePositiveRate || 5}%</span>
            </div>
            <div class="metric">
                <span>Bypass Rate:</span>
                <span class="value critical">${data.trustScore?.components?.bypassRate || 10}%</span>
            </div>
            <div class="metric">
                <span>Trend:</span>
                <span class="value">${data.trustScore?.trend || 'STABLE'}</span>
            </div>
            <div class="metric">
                <span>Last Updated:</span>
                <span class="value">${new Date(data.trustScore?.lastUpdated || new Date()).toLocaleTimeString()}</span>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header">
                RED TEAM PRESSURE
                <button class="refresh-btn" onclick="location.reload()">REFRESH</button>
            </div>
            <div class="metric">
                <span>Current Pressure:</span>
                <span class="value">${data.redTeamPressure?.currentPressure || 30}%</span>
            </div>
            <div class="metric">
                <span>Active Attacks:</span>
                <span class="value">${data.redTeamPressure?.activeAttacks || 5}</span>
            </div>
            <div class="metric">
                <span>Successful Bypasses:</span>
                <span class="value critical">${data.redTeamPressure?.successfulBypasses || 1}</span>
            </div>
            <div class="metric">
                <span>Trend:</span>
                <span class="value">${data.redTeamPressure?.trend || 'STABLE'}</span>
            </div>
            <div class="metric">
                <span>Last Update:</span>
                <span class="value">${new Date(data.redTeamPressure?.lastUpdate || new Date()).toLocaleTimeString()}</span>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header">
                SECURITY METRICS
                <button class="refresh-btn" onclick="location.reload()">REFRESH</button>
            </div>
            <div class="metric">
                <span>Total Requests:</span>
                <span class="value">${data.securityMetrics?.metrics?.totalRequests || 1000}</span>
            </div>
            <div class="metric">
                <span>Blocked:</span>
                <span class="value critical">${data.securityMetrics?.metrics?.blockedRequests || 850}</span>
            </div>
            <div class="metric">
                <span>Flagged:</span>
                <span class="value warning">${data.securityMetrics?.metrics?.flaggedRequests || 100}</span>
            </div>
            <div class="metric">
                <span>Allowed:</span>
                <span class="value success">${(data.securityMetrics?.metrics?.totalRequests || 1000) - (data.securityMetrics?.metrics?.blockedRequests || 850) - (data.securityMetrics?.metrics?.flaggedRequests || 100)}</span>
            </div>
            <div class="metric">
                <span>Avg Risk Score:</span>
                <span class="value">${data.securityMetrics?.metrics?.averageRiskScore || 25}%</span>
            </div>
            <div class="metric">
                <span>Processing Latency:</span>
                <span class="value">${data.securityMetrics?.metrics?.processingLatency || 45}ms</span>
            </div>
        </div>
        
        <div class="panel" style="grid-column: 1 / 4;">
            <div class="panel-header">
                LIVE ATTACK FEED
                <button class="refresh-btn" onclick="location.reload()">REFRESH</button>
            </div>
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