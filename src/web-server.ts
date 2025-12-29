/**
 * TrustLens Web Server
 * Launches the web interface for the TrustLens AI Security Platform
 */

import { DatasetAPIServer } from './api/server';

async function startWebServer() {
  console.log('🚀 Starting TrustLens AI Security Platform Web Server...');
  
  const server = new DatasetAPIServer(3000);
  
  try {
    await server.start();
    
    console.log('✅ TrustLens platform is ready!');
    console.log('🌐 Open your browser and navigate to: http://localhost:3000');
    console.log('');
    console.log('Available features:');
    console.log('  • AI Firewall - Real-time prompt analysis');
    console.log('  • Security Dashboard - Threat monitoring');
    console.log('  • Red Team Engine - Adversarial testing');
    console.log('  • Dataset Management - Attack data versioning');
    console.log('  • Trust Score - User behavior analysis');
    console.log('  • Audit Logs - Tamper-evident logging');
    console.log('');
    console.log('Press Ctrl+C to stop the server');
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown handling
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down TrustLens platform...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down TrustLens platform...');
  process.exit(0);
});

// Start the server
startWebServer();