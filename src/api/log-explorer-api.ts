/**
 * Log Explorer API Endpoints
 * Professional SOC-style log filtering, search, and export functionality
 */

import express, { Request, Response, NextFunction } from 'express';
import { EnhancedAuditService } from './audit-service';
import { LogFilter, LogSearchQuery, LogExportOptions } from '../ui/log-explorer';
import { authenticateRequest } from './firewall';

export interface LogExplorerAPI {
  searchLogs(query: LogSearchQuery, filter?: LogFilter, page?: number, pageSize?: number): Promise<any>;
  filterLogs(filter: LogFilter, page?: number, pageSize?: number): Promise<any>;
  exportLogs(format: 'CSV' | 'JSON' | 'SIEM', filters?: any): Promise<string>;
  getLogStatistics(): Promise<any>;
  getServiceStatus(): Promise<any>;
}

export class LogExplorerService implements LogExplorerAPI {
  private auditService: EnhancedAuditService;

  constructor(auditService: EnhancedAuditService) {
    this.auditService = auditService;
  }

  async searchLogs(
    query: LogSearchQuery, 
    filter?: LogFilter, 
    page: number = 1, 
    pageSize: number = 100
  ) {
    return await this.auditService.searchLogs(query, filter, page, pageSize);
  }

  async filterLogs(filter: LogFilter, page: number = 1, pageSize: number = 100) {
    return await this.auditService.filterLogs(filter, page, pageSize);
  }

  async exportLogs(format: 'CSV' | 'JSON' | 'SIEM', filters?: any) {
    return await this.auditService.exportLogs({
      format,
      includeIntegrity: true,
      filters
    });
  }

  async getLogStatistics() {
    const status = await this.auditService.getServiceStatus();
    const complianceReport = await this.auditService.generateComplianceReport();
    
    return {
      totalLogs: status.totalLogs,
      integrityStatus: status.integrityStatus,
      complianceStatus: status.complianceStatus,
      lastVerification: status.lastVerification,
      integrityVerification: complianceReport.integrityVerification,
      retentionStatus: complianceReport.retentionStatus
    };
  }

  async getServiceStatus() {
    return await this.auditService.getServiceStatus();
  }

  async generateSOCReport() {
    return await this.auditService.generateSOCReport();
  }
}

// Input validation middleware for log explorer
export function validateLogSearchRequest(req: Request, res: Response, next: NextFunction) {
  const { query, filter, page, pageSize } = req.body;

  // Validate search query if provided
  if (query) {
    if (!query.searchTerm || typeof query.searchTerm !== 'string') {
      return res.status(400).json({
        error: 'Validation error',
        message: 'searchTerm is required and must be a string'
      });
    }

    if (!Array.isArray(query.searchFields) || query.searchFields.length === 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'searchFields must be a non-empty array'
      });
    }

    const validFields = ['prompt', 'explanation', 'userId', 'sessionId'];
    const invalidFields = query.searchFields.filter((field: string) => !validFields.includes(field));
    if (invalidFields.length > 0) {
      return res.status(400).json({
        error: 'Validation error',
        message: `Invalid search fields: ${invalidFields.join(', ')}. Valid fields: ${validFields.join(', ')}`
      });
    }
  }

  // Validate filter if provided
  if (filter) {
    if (filter.startTime && !(filter.startTime instanceof Date) && isNaN(Date.parse(filter.startTime))) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'startTime must be a valid date'
      });
    }

    if (filter.endTime && !(filter.endTime instanceof Date) && isNaN(Date.parse(filter.endTime))) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'endTime must be a valid date'
      });
    }

    if (filter.riskScoreMin !== undefined && (typeof filter.riskScoreMin !== 'number' || filter.riskScoreMin < 0 || filter.riskScoreMin > 100)) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'riskScoreMin must be a number between 0 and 100'
      });
    }

    if (filter.riskScoreMax !== undefined && (typeof filter.riskScoreMax !== 'number' || filter.riskScoreMax < 0 || filter.riskScoreMax > 100)) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'riskScoreMax must be a number between 0 and 100'
      });
    }
  }

  // Validate pagination
  if (page !== undefined && (!Number.isInteger(page) || page < 1)) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'page must be a positive integer'
    });
  }

  if (pageSize !== undefined && (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 1000)) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'pageSize must be an integer between 1 and 1000'
    });
  }

  next();
}

export function validateExportRequest(req: Request, res: Response, next: NextFunction) {
  const { format, filters } = req.body;

  if (!format || !['CSV', 'JSON', 'SIEM'].includes(format)) {
    return res.status(400).json({
      error: 'Validation error',
      message: 'format must be one of: CSV, JSON, SIEM'
    });
  }

  // Validate filters if provided (similar to search validation)
  if (filters) {
    if (filters.startTime && isNaN(Date.parse(filters.startTime))) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'filters.startTime must be a valid date'
      });
    }

    if (filters.endTime && isNaN(Date.parse(filters.endTime))) {
      return res.status(400).json({
        error: 'Validation error',
        message: 'filters.endTime must be a valid date'
      });
    }
  }

  next();
}

// Create Express router for log explorer endpoints
export function createLogExplorerRouter(logExplorerService: LogExplorerService): express.Router {
  const router = express.Router();

  // Apply middleware
  router.use(express.json({ limit: '10mb' }));
  router.use(authenticateRequest);

  // Search logs endpoint
  router.post('/search', validateLogSearchRequest, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { query, filter, page = 1, pageSize = 100 } = req.body;

      // Convert date strings to Date objects if provided
      if (filter) {
        if (filter.startTime) filter.startTime = new Date(filter.startTime);
        if (filter.endTime) filter.endTime = new Date(filter.endTime);
      }

      const result = await logExplorerService.searchLogs(query, filter, page, pageSize);
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Filter logs endpoint
  router.post('/filter', validateLogSearchRequest, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { filter, page = 1, pageSize = 100 } = req.body;

      // Convert date strings to Date objects if provided
      if (filter) {
        if (filter.startTime) filter.startTime = new Date(filter.startTime);
        if (filter.endTime) filter.endTime = new Date(filter.endTime);
      }

      const result = await logExplorerService.filterLogs(filter, page, pageSize);
      res.json(result);
    } catch (error) {
      next(error);
    }
  });

  // Export logs endpoint
  router.post('/export', validateExportRequest, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { format, filters } = req.body;

      // Convert date strings to Date objects if provided
      if (filters) {
        if (filters.startTime) filters.startTime = new Date(filters.startTime);
        if (filters.endTime) filters.endTime = new Date(filters.endTime);
      }

      const exportData = await logExplorerService.exportLogs(format, filters);

      // Set appropriate content type and filename
      let contentType = 'text/plain';
      let filename = `audit_logs_${new Date().toISOString().split('T')[0]}`;

      switch (format) {
        case 'JSON':
          contentType = 'application/json';
          filename += '.json';
          break;
        case 'CSV':
          contentType = 'text/csv';
          filename += '.csv';
          break;
        case 'SIEM':
          contentType = 'text/plain';
          filename += '.cef';
          break;
      }

      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.send(exportData);
    } catch (error) {
      next(error);
    }
  });

  // Get log statistics endpoint
  router.get('/statistics', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const statistics = await logExplorerService.getLogStatistics();
      res.json(statistics);
    } catch (error) {
      next(error);
    }
  });

  // Get service status endpoint
  router.get('/status', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const status = await logExplorerService.getServiceStatus();
      res.json(status);
    } catch (error) {
      next(error);
    }
  });

  // Generate SOC report endpoint
  router.get('/soc-report', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const report = await logExplorerService.generateSOCReport();
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', 'attachment; filename="soc_report.txt"');
      res.send(report);
    } catch (error) {
      next(error);
    }
  });

  // Bulk export endpoint for large datasets
  router.post('/bulk-export', validateExportRequest, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { format, filters, batchSize = 1000 } = req.body;

      // Convert date strings to Date objects if provided
      if (filters) {
        if (filters.startTime) filters.startTime = new Date(filters.startTime);
        if (filters.endTime) filters.endTime = new Date(filters.endTime);
      }

      // Set up streaming response
      let contentType = 'text/plain';
      let filename = `bulk_audit_logs_${new Date().toISOString().split('T')[0]}`;

      switch (format) {
        case 'JSON':
          contentType = 'application/json';
          filename += '.json';
          break;
        case 'CSV':
          contentType = 'text/csv';
          filename += '.csv';
          break;
        case 'SIEM':
          contentType = 'text/plain';
          filename += '.cef';
          break;
      }

      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Transfer-Encoding', 'chunked');

      // For now, just export all at once (in a real implementation, this would stream)
      const exportData = await logExplorerService.exportLogs(format, filters);
      res.send(exportData);
    } catch (error) {
      next(error);
    }
  });

  // Error handling middleware
  router.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error('Log Explorer API Error:', err);

    if (err.message.includes('Validation error')) {
      return res.status(400).json({
        error: 'Validation error',
        message: err.message
      });
    }

    // Default to 500 for unexpected errors
    res.status(500).json({
      error: 'Internal server error',
      message: 'An unexpected error occurred while processing the log request'
    });
  });

  return router;
}