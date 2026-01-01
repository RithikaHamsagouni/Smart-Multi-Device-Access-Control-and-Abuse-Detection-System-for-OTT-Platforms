const { redis } = require("../config/redis");
const Device = require("../models/Device");

class DeviceTrustScorer {
  constructor() {
    this.weights = {
      loginFrequency: 20,
      deviceAge: 15,
      geoConsistency: 25,
      failedAttempts: -30,
      suspiciousHours: -10,
      deviceSharing: -25,
      vpnUsage: -15
    };
  }

  async calculateTrustScore(userId, deviceId, ipAddress) {
    let score = 50; // Base score
    const factors = [];

    // 1. Login Frequency Score (0-20 points)
    const frequencyScore = await this.getLoginFrequencyScore(userId, deviceId);
    score += frequencyScore;
    factors.push({ factor: "Login Frequency", score: frequencyScore });

    // 2. Device Age Score (0-15 points)
    const ageScore = await this.getDeviceAgeScore(userId, deviceId);
    score += ageScore;
    factors.push({ factor: "Device Age", score: ageScore });

    // 3. Geographic Consistency (0-25 points)
    const geoScore = await this.getGeoConsistencyScore(userId, deviceId, ipAddress);
    score += geoScore;
    factors.push({ factor: "Geo Consistency", score: geoScore });

    // 4. Failed Login Attempts (-30 to 0 points)
    const failedScore = await this.getFailedAttemptsScore(userId, deviceId);
    score += failedScore;
    factors.push({ factor: "Failed Attempts", score: failedScore });

    // 5. Suspicious Login Hours (-10 to 0 points)
    const hoursScore = this.getSuspiciousHoursScore();
    score += hoursScore;
    factors.push({ factor: "Login Hours", score: hoursScore });

    // 6. Device Sharing Detection (-25 to 0 points)
    const sharingScore = await this.getDeviceSharingScore(deviceId);
    score += sharingScore;
    factors.push({ factor: "Device Sharing", score: sharingScore });

    // 7. VPN/Proxy Detection (-15 to 0 points)
    const vpnScore = this.getVPNScore(ipAddress);
    score += vpnScore;
    factors.push({ factor: "VPN Usage", score: vpnScore });

    // Clamp score between 0-100
    score = Math.max(0, Math.min(100, score));

    // Store score in Redis
    await this.storeTrustScore(userId, deviceId, score, factors);

    return {
      score: Math.round(score),
      level: this.getTrustLevel(score),
      factors,
      timestamp: Date.now()
    };
  }

  // Calculate login frequency score
  async getLoginFrequencyScore(userId, deviceId) {
    const key = `device:${deviceId}:login_count`;
    const count = await redis.get(key) || 0;

    // More logins = higher trust
    if (count >= 50) return 20;
    if (count >= 30) return 15;
    if (count >= 15) return 10;
    if (count >= 5) return 5;
    return 0;
  }

  // Calculate device age score
  async getDeviceAgeScore(userId, deviceId) {
    try {
      const device = await Device.findOne({ userId, deviceId });
      if (!device) return 0;

      const ageInDays = (Date.now() - device.createdAt) / (1000 * 60 * 60 * 24);

      // Older devices = higher trust
      if (ageInDays >= 180) return 15;
      if (ageInDays >= 90) return 12;
      if (ageInDays >= 30) return 8;
      if (ageInDays >= 7) return 4;
      return 0;
    } catch (err) {
      return 0;
    }
  }

  // Calculate geographic consistency score
  async getGeoConsistencyScore(userId, deviceId, ipAddress) {
    const geoip = require("geoip-lite");
    const geo = geoip.lookup(ipAddress);
    if (!geo) return 0;

    const key = `device:${deviceId}:countries`;
    const countries = await redis.smembers(key);

    if (countries.length === 0) {
      // First login from this device
      await redis.sadd(key, geo.country);
      await redis.expire(key, 86400 * 30); // 30 days
      return 10;
    }

    // Consistent country = higher trust
    if (countries.includes(geo.country)) {
      if (countries.length === 1) return 25; // Always same country
      if (countries.length === 2) return 15; // 2 countries (travel/VPN)
      return 5; // Multiple countries
    }

    // New country
    await redis.sadd(key, geo.country);
    return countries.length > 3 ? -10 : 0;
  }

  // Calculate failed attempts penalty
  async getFailedAttemptsScore(userId, deviceId) {
    const key = `device:${deviceId}:failed_attempts`;
    const failures = parseInt(await redis.get(key) || 0);

    if (failures === 0) return 0;
    if (failures <= 2) return -5;
    if (failures <= 5) return -15;
    return -30; // High failure rate
  }

  // Detect suspicious login hours
  getSuspiciousHoursScore() {
    const hour = new Date().getHours();
    
    // Login at odd hours (2 AM - 6 AM) is slightly suspicious
    if (hour >= 2 && hour <= 6) return -10;
    return 0;
  }

  // Detect if device is shared across multiple accounts
  async getDeviceSharingScore(deviceId) {
    const key = `device:${deviceId}:users`;
    const users = await redis.smembers(key);

    if (users.length <= 1) return 0;
    if (users.length === 2) return -10;
    return -25; // Device used by 3+ accounts = high risk
  }

  // Simple VPN detection (basic)
  getVPNScore(ipAddress) {
    // Common VPN/datacenter IP ranges (simplified)
    const suspiciousRanges = [
      "10.", "172.16.", "192.168.", // Private ranges
    ];

    for (const range of suspiciousRanges) {
      if (ipAddress.startsWith(range)) return -15;
    }

    return 0;
  }

  // Store trust score
  async storeTrustScore(userId, deviceId, score, factors) {
    const key = `trust:${userId}:${deviceId}`;
    const data = {
      score,
      factors,
      timestamp: Date.now()
    };
    
    await redis.setex(key, 86400, JSON.stringify(data)); // 24h cache
  }

  // Get trust level label
  getTrustLevel(score) {
    if (score >= 80) return "HIGH";
    if (score >= 60) return "MEDIUM";
    if (score >= 40) return "LOW";
    return "CRITICAL";
  }

  // Increment login counter
  async incrementLoginCount(deviceId) {
    const key = `device:${deviceId}:login_count`;
    await redis.incr(key);
    await redis.expire(key, 86400 * 90); // 90 days
  }

  // Record failed attempt
  async recordFailedAttempt(deviceId) {
    const key = `device:${deviceId}:failed_attempts`;
    await redis.incr(key);
    await redis.expire(key, 3600); // Reset after 1 hour
  }

  // Track device-user mapping
  async trackDeviceUser(deviceId, userId) {
    const key = `device:${deviceId}:users`;
    await redis.sadd(key, userId.toString());
    await redis.expire(key, 86400 * 30); // 30 days
  }
}

module.exports = new DeviceTrustScorer();