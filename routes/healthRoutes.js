const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const logger = require('../utils/logger');

/**
 * @route GET /api/health
 * @desc Basic health check
 * @access Public
 */
router.get('/', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    service: 'SMTP EVA Email Verification'
  });
});

/**
 * @route GET /api/health/detailed
 * @desc Detailed health check with system information
 * @access Public
 */
router.get('/detailed', async (req, res) => {
  try {
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      service: {
        name: 'SMTP EVA Email Verification',
        version: '1.0.0',
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
      },
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        memory: {
          used: Math.round((process.memoryUsage().heapUsed / 1024 / 1024) * 100) / 100,
          total: Math.round((process.memoryUsage().heapTotal / 1024 / 1024) * 100) / 100,
          external: Math.round((process.memoryUsage().external / 1024 / 1024) * 100) / 100
        },
        cpu: {
          loadAverage: process.platform !== 'win32' ? require('os').loadavg() : [0, 0, 0]
        }
      },
      database: {
        mongodb: {
          status: 'unknown',
          readyState: mongoose.connection.readyState,
          host: mongoose.connection.host || 'unknown',
          name: mongoose.connection.name || 'unknown'
        }
      },
      checks: []
    };

    // Check MongoDB connection
    try {
      if (mongoose.connection.readyState === 1) {
        health.database.mongodb.status = 'connected';
        health.checks.push({ name: 'MongoDB', status: 'OK' });
      } else {
        health.database.mongodb.status = 'disconnected';
        health.checks.push({ name: 'MongoDB', status: 'ERROR', message: 'Database not connected' });
        health.status = 'DEGRADED';
      }
    } catch (error) {
      health.database.mongodb.status = 'error';
      health.checks.push({ name: 'MongoDB', status: 'ERROR', message: error.message });
      health.status = 'DEGRADED';
    }

    // Check memory usage
    const memoryUsagePercent = (process.memoryUsage().heapUsed / process.memoryUsage().heapTotal) * 100;
    if (memoryUsagePercent > 90) {
      health.checks.push({ name: 'Memory Usage', status: 'WARNING', message: 'High memory usage detected' });
      if (health.status === 'OK') health.status = 'WARNING';
    } else {
      health.checks.push({ name: 'Memory Usage', status: 'OK' });
    }

    // Check disk space (simplified)
    try {
      const fs = require('fs');
      const stats = fs.statSync('./');
      health.checks.push({ name: 'File System', status: 'OK' });
    } catch (error) {
      health.checks.push({ name: 'File System', status: 'ERROR', message: error.message });
      health.status = 'ERROR';
    }

    res.json(health);

  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(500).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

/**
 * @route GET /api/health/ready
 * @desc Readiness probe for Kubernetes/Docker
 * @access Public
 */
router.get('/ready', async (req, res) => {
  try {
    const checks = [];
    let ready = true;

    // Check database connection
    if (mongoose.connection.readyState === 1) {
      checks.push({ name: 'Database', status: 'ready' });
    } else {
      checks.push({ name: 'Database', status: 'not ready' });
      ready = false;
    }

    // Check if application is initialized
    checks.push({ name: 'Application', status: 'ready' });

    if (ready) {
      res.json({
        status: 'ready',
        checks: checks,
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(503).json({
        status: 'not ready',
        checks: checks,
        timestamp: new Date().toISOString()
      });
    }

  } catch (error) {
    logger.error('Readiness check failed:', error);
    res.status(503).json({
      status: 'not ready',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @route GET /api/health/live
 * @desc Liveness probe for Kubernetes/Docker
 * @access Public
 */
router.get('/live', (req, res) => {
  // Simple liveness check - if the server can respond, it's alive
  res.json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/**
 * @route GET /api/health/metrics
 * @desc Basic metrics for monitoring
 * @access Public
 */
router.get('/metrics', (req, res) => {
  try {
    const metrics = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: {
        rss: process.memoryUsage().rss,
        heapTotal: process.memoryUsage().heapTotal,
        heapUsed: process.memoryUsage().heapUsed,
        external: process.memoryUsage().external,
        arrayBuffers: process.memoryUsage().arrayBuffers || 0
      },
      cpu: {
        userTime: process.cpuUsage().user,
        systemTime: process.cpuUsage().system
      },
      eventLoop: {
        lag: Date.now() - process.hrtime.bigint() / 1000000n
      },
      database: {
        connectionState: mongoose.connection.readyState,
        connectionCount: mongoose.connections.length
      }
    };

    res.json(metrics);

  } catch (error) {
    logger.error('Metrics collection failed:', error);
    res.status(500).json({
      error: 'Failed to collect metrics',
      timestamp: new Date().toISOString()
    });
  }
});

module.exports = router; 