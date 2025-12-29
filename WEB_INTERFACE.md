# TrustLens AI Security Platform - Web Interface

## Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the web server:**
   ```bash
   npm start
   ```
   or
   ```bash
   npm run web
   ```

3. **Open in Chrome:**
   - Main Interface: `http://localhost:3000`
   - Professional SOC Dashboard: `http://localhost:3000/dashboard`

## Features Available in Web Interface

### 🌐 Main Interface (`http://localhost:3000`)
- Overview of all platform features
- Interactive testing tools
- Quick access to all components

### 📊 Professional SOC Dashboard (`http://localhost:3000/dashboard`)
- **Real-time monitoring** with SOC-style interface
- **Live attack feed** with detailed threat analysis
- **Trust score monitoring** with component breakdown
- **Red team pressure indicators** and trend analysis
- **Security metrics** with comprehensive statistics
- **Regression alerts** for defense performance monitoring
- **Attack evolution trees** showing mutation patterns
- **Auto-refresh** capabilities for live monitoring

### 🛡️ AI Firewall
- Real-time prompt analysis
- Risk scoring and threat detection
- Interactive testing interface

### 🔴 Red Team Engine
- Automated adversarial testing
- Attack simulation results
- Evolution tracking and lineage analysis

### 📚 Dataset Management
- Attack dataset versioning
- Data export capabilities
- Research data management

### ⭐ Trust Score
- Dynamic user trust scoring
- Behavior pattern analysis
- Trust metric calculation

### 📋 Audit Logs
- Tamper-evident logging
- Compliance reporting
- Integrity verification

## API Endpoints

The web interface connects to these REST API endpoints:

### Core Endpoints
- `GET /` - Main web interface
- `GET /dashboard` - Professional SOC dashboard
- `GET /health` - Server health check

### Dashboard APIs
- `GET /api/dashboard/data` - Complete dashboard data
- `GET /api/dashboard/stats` - Security metrics
- `GET /api/dashboard/evolution/:attackId` - Attack evolution trees

### Security APIs
- `POST /api/firewall/analyze` - Analyze prompts
- `GET /api/firewall/stats` - Firewall statistics
- `POST /api/trust/calculate` - Calculate trust scores
- `POST /api/redteam/run` - Run red team tests

### Data Management APIs
- `GET /api/datasets` - List datasets
- `POST /api/datasets` - Create datasets
- `POST /api/attacks/search` - Search attacks

## Professional SOC Dashboard Features

The SOC dashboard (`/dashboard`) implements the comprehensive dashboard from `src/ui/dashboard.ts`:

### Real-time Monitoring
- **Live Attack Feed**: Real-time display of security events
- **Trust Score Tracking**: Component-level trust metrics
- **Red Team Pressure**: Active attack monitoring
- **Security Metrics**: Request processing statistics

### Advanced Analytics
- **Attack Evolution Trees**: Visual representation of attack mutations
- **Regression Alerts**: Performance degradation warnings  
- **Severity Distribution**: Threat categorization
- **Trend Analysis**: Historical performance tracking

### SOC-Style Interface
- **Terminal-style design** for professional security operations
- **Color-coded alerts** (Critical: Red, Warning: Yellow, Success: Green)
- **Real-time updates** with configurable refresh intervals
- **Keyboard shortcuts** and professional workflow support

## Development

To run in development mode with auto-reload:
```bash
npm run dev
```

To run tests:
```bash
npm test
```

## Architecture

The web interface integrates:
- **Frontend**: Professional HTML/CSS/JavaScript interfaces
- **Backend**: Express.js with TypeScript and comprehensive APIs
- **Dashboard Logic**: Full implementation from `src/ui/dashboard.ts`
- **Security Engines**: Real integration with firewall, red team, and trust score engines
- **Database**: SQLite for data persistence with audit logging

## Browser Compatibility

Optimized for modern browsers including:
- Chrome (recommended)
- Firefox
- Safari
- Edge

## Security Features

- CORS enabled for cross-origin requests
- Request logging and monitoring
- Input validation and sanitization
- Secure API endpoints
- Real-time threat detection and response