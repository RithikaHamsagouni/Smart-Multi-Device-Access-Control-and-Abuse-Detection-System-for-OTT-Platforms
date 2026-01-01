const Redis = require("ioredis");

const redis = new Redis({
  host: process.env.REDIS_HOST || "localhost",
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD || undefined,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  },
  maxRetriesPerRequest: 3
});

redis.on("connect", () => {
  console.log("✅ Redis connected successfully");
});

redis.on("error", (err) => {
  console.error("❌ Redis connection error:", err);
});

// Helper functions for session management
const sessionHelpers = {
  // Store session with expiry (24 hours)
  async createSession(userId, deviceId, token, metadata = {}) {
    const key = `session:${userId}:${deviceId}`;
    const sessionData = {
      token,
      deviceId,
      userId,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      ...metadata
    };
    
    await redis.setex(key, 86400, JSON.stringify(sessionData)); // 24h expiry
    await redis.sadd(`user:${userId}:sessions`, deviceId);
    return sessionData;
  },

  // Get session
  async getSession(userId, deviceId) {
    const key = `session:${userId}:${deviceId}`;
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  },

  // Get all active sessions for a user
  async getUserSessions(userId) {
    const deviceIds = await redis.smembers(`user:${userId}:sessions`);
    const sessions = [];
    
    for (const deviceId of deviceIds) {
      const session = await this.getSession(userId, deviceId);
      if (session) {
        sessions.push(session);
      } else {
        // Clean up stale references
        await redis.srem(`user:${userId}:sessions`, deviceId);
      }
    }
    
    return sessions.sort((a, b) => a.createdAt - b.createdAt);
  },

  // Delete session (logout)
  async deleteSession(userId, deviceId) {
    const key = `session:${userId}:${deviceId}`;
    await redis.del(key);
    await redis.srem(`user:${userId}:sessions`, deviceId);
  },

  // Update last activity
  async updateActivity(userId, deviceId) {
    const session = await this.getSession(userId, deviceId);
    if (session) {
      session.lastActivity = Date.now();
      await redis.setex(
        `session:${userId}:${deviceId}`,
        86400,
        JSON.stringify(session)
      );
    }
  },

  // Check if session exists and is valid
  async validateSession(userId, deviceId, token) {
    const session = await this.getSession(userId, deviceId);
    return session && session.token === token;
  }
};

module.exports = { redis, sessionHelpers };