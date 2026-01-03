const { redis } = require("../config/redis");
const sendEmailAlert = require("./sendEmailAlert");
const sendSlackAlert = require("./sendSlackAlert");
const { blockUser } = require("../middleware/rateLimiter");

class AlertRulesEngine {
  constructor() {
    // Configurable alert rules
    this.rules = [
      {
        id: "geo_impossibility",
        name: "Geographic Impossibility Detected",
        condition: (context) => context.geoCheck?.isImpossible === true,
        severity: "CRITICAL",
        actions: ["email", "slack", "block_session"],
        message: (context) => 
          `User ${context.email} attempted login from impossible location: ${context.geoCheck.reason}`
      },
      {
        id: "trust_score_critical",
        name: "Critical Trust Score",
        condition: (context) => context.trustScore < 40,
        severity: "HIGH",
        actions: ["email", "slack"],
        message: (context) => 
          `User ${context.email} has critical trust score: ${context.trustScore}/100`
      },
      {
        id: "device_sharing",
        name: "Device Sharing Detected",
        condition: (context) => context.deviceUserCount > 2,
        severity: "MEDIUM",
        actions: ["email", "flag"],
        message: (context) => 
          `Device ${context.deviceId.substring(0, 8)} is being used by ${context.deviceUserCount} accounts`
      },
      {
        id: "multiple_failed_logins",
        name: "Multiple Failed Login Attempts",
        condition: (context) => context.failedAttempts >= 5,
        severity: "HIGH",
        actions: ["email", "temporary_block"],
        message: (context) => 
          `User ${context.email} has ${context.failedAttempts} failed login attempts`
      },
      {
        id: "session_limit_exceeded",
        name: "Session Limit Exceeded",
        condition: (context) => context.activeSessions > context.maxSessions,
        severity: "MEDIUM",
        actions: ["email"],
        message: (context) => 
          `User ${context.email} exceeded session limit: ${context.activeSessions}/${context.maxSessions}`
      },
      {
        id: "unusual_login_hours",
        name: "Login During Unusual Hours",
        condition: (context) => {
          const hour = new Date().getHours();
          return hour >= 2 && hour <= 5; // 2 AM - 5 AM
        },
        severity: "LOW",
        actions: ["log"],
        message: (context) => 
          `User ${context.email} logged in at unusual hour: ${new Date().toLocaleTimeString()}`
      },
      {
        id: "vpn_detected",
        name: "VPN/Proxy Usage Detected",
        condition: (context) => context.isVPN === true,
        severity: "MEDIUM",
        actions: ["email", "flag"],
        message: (context) => 
          `User ${context.email} is using VPN/Proxy from ${context.location?.country}`
      },
      {
        id: "rapid_location_changes",
        name: "Rapid Location Changes",
        condition: (context) => context.locationChangeCount > 3,
        severity: "HIGH",
        actions: ["email", "slack", "flag"],
        message: (context) => 
          `User ${context.email} changed locations ${context.locationChangeCount} times in 24h`
      },
      {
        id: "new_device_high_risk",
        name: "New Device from High-Risk Location",
        condition: (context) => context.isNewDevice && context.trustScore < 50,
        severity: "MEDIUM",
        actions: ["email"],
        message: (context) => 
          `New device detected for ${context.email} with low trust score: ${context.trustScore}/100`
      },
      {
        id: "account_takeover_attempt",
        name: "Potential Account Takeover",
        condition: (context) => 
          context.passwordChanged && context.trustScore < 60,
        severity: "CRITICAL",
        actions: ["email", "slack", "temporary_block"],
        message: (context) => 
          `Potential account takeover for ${context.email} - password changed with low trust score`
      }
    ];
  }

  // Evaluate all rules against context
  async evaluateRules(context) {
    const triggeredAlerts = [];

    for (const rule of this.rules) {
      try {
        if (rule.condition(context)) {
          const alert = {
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            message: rule.message(context),
            timestamp: Date.now(),
            context: {
              userId: context.userId,
              email: context.email,
              deviceId: context.deviceId,
              ipAddress: context.ipAddress,
              location: context.location
            }
          };

          // Execute actions
          await this.executeActions(rule.actions, alert, context);

          // Store alert in Redis
          await this.storeAlert(alert);

          triggeredAlerts.push(alert);

          console.log(`🚨 Alert triggered: ${rule.name} for ${context.email}`);
        }
      } catch (err) {
        console.error(`Error evaluating rule ${rule.id}:`, err);
      }
    }

    return triggeredAlerts;
  }

  // Execute actions based on rule configuration
  async executeActions(actions, alert, context) {
    for (const action of actions) {
      try {
        switch (action) {
          case "email":
            await sendEmailAlert(alert, context);
            break;

          case "slack":
            await sendSlackAlert(alert, context);
            break;

          case "block_session":
            // Terminate current session
            const { sessionHelpers } = require("../config/redis");
            await sessionHelpers.deleteSession(context.userId, context.deviceId);
            break;

          case "temporary_block":
            // Block user for 1 hour
            await blockUser(context.userId, 3600);
            break;

          case "flag":
            // Flag user for manual review
            await this.flagUser(context.userId, alert);
            break;

          case "log":
            // Just log to console/file
            console.log(`📝 ${alert.message}`);
            break;

          default:
            console.warn(`Unknown action: ${action}`);
        }
      } catch (err) {
        console.error(`Error executing action ${action}:`, err);
      }
    }
  }

  // Store alert in Redis for dashboard display
  async storeAlert(alert) {
    const key = `alerts:${Date.now()}`;
    await redis.setex(key, 86400 * 7, JSON.stringify(alert)); // 7 days retention

    // Add to sorted set for easy retrieval
    await redis.zadd("alerts:sorted", Date.now(), key);

    // Keep only last 1000 alerts
    await redis.zremrangebyrank("alerts:sorted", 0, -1001);
  }

  // Flag user for manual review
  async flagUser(userId, alert) {
    const flagKey = `user:${userId}:flagged`;
    const flagData = {
      reason: alert.message,
      severity: alert.severity,
      timestamp: Date.now()
    };

    await redis.setex(flagKey, 86400 * 30, JSON.stringify(flagData)); // 30 days

    // Add to flagged users set
    await redis.sadd("flagged_users", userId.toString());
  }

  // Get recent alerts
  async getRecentAlerts(limit = 50) {
    const keys = await redis.zrevrange("alerts:sorted", 0, limit - 1);
    const alerts = [];

    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        alerts.push(JSON.parse(data));
      }
    }

    return alerts;
  }

  // Get alerts by severity
  async getAlertsBySeverity(severity, limit = 50) {
    const allAlerts = await this.getRecentAlerts(limit * 2);
    return allAlerts.filter(alert => alert.severity === severity).slice(0, limit);
  }

  // Get user-specific alerts
  async getUserAlerts(userId, limit = 20) {
    const allAlerts = await this.getRecentAlerts(100);
    return allAlerts
      .filter(alert => alert.context.userId === userId)
      .slice(0, limit);
  }

  // Check if user is flagged
  async isUserFlagged(userId) {
    const isFlagged = await redis.sismember("flagged_users", userId.toString());
    
    if (isFlagged) {
      const flagKey = `user:${userId}:flagged`;
      const flagData = await redis.get(flagKey);
      return flagData ? JSON.parse(flagData) : { flagged: true };
    }

    return null;
  }

  // Clear user flag
  async clearUserFlag(userId) {
    await redis.srem("flagged_users", userId.toString());
    await redis.del(`user:${userId}:flagged`);
  }

  // Get alert statistics
  async getAlertStats() {
    const alerts = await this.getRecentAlerts(100);
    
    const stats = {
      total: alerts.length,
      bySeverity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
      },
      byRule: {},
      last24Hours: 0,
      flaggedUsers: await redis.scard("flagged_users")
    };

    const oneDayAgo = Date.now() - 86400000;

    for (const alert of alerts) {
      stats.bySeverity[alert.severity]++;
      stats.byRule[alert.ruleId] = (stats.byRule[alert.ruleId] || 0) + 1;
      
      if (alert.timestamp > oneDayAgo) {
        stats.last24Hours++;
      }
    }

    return stats;
  }
}

module.exports = new AlertRulesEngine();