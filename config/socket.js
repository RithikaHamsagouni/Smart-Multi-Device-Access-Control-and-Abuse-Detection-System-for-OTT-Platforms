const { Server } = require("socket.io");
const { sessionHelpers, redis } = require("./redis");
const Device = require("../models/Device");
const User = require("../models/User");
const geoip = require("geoip-lite");

let io;

function initializeSocket(server) {
  io = new Server(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  io.on("connection", (socket) => {
    console.log("📡 Admin dashboard connected:", socket.id);

    // Send initial dashboard data
    socket.on("getDashboardData", async () => {
      const data = await getDashboardData();
      socket.emit("dashboardData", data);
    });

    // Real-time updates every 5 seconds
    const interval = setInterval(async () => {
      const data = await getDashboardData();
      socket.emit("dashboardUpdate", data);
    }, 5000);

    socket.on("disconnect", () => {
      clearInterval(interval);
      console.log("📡 Admin dashboard disconnected:", socket.id);
    });
  });

  return io;
}

async function getDashboardData() {
  try {
    // Get all users
    const users = await User.find().lean();
    
    // Collect session data
    const sessionsData = {
      activeSessions: [],
      totalSessions: 0,
      byPlan: { BASIC: 0, STANDARD: 0, PREMIUM: 0 },
      byTrustLevel: { HIGH: 0, MEDIUM: 0, LOW: 0, CRITICAL: 0 },
      geoDistribution: {},
      recentActivity: []
    };

    for (const user of users) {
      const sessions = await sessionHelpers.getUserSessions(user._id);
      sessionsData.totalSessions += sessions.length;
      sessionsData.byPlan[user.plan] += sessions.length;

      for (const session of sessions) {
        // Get device info
        const device = await Device.findOne({
          userId: user._id,
          deviceId: session.deviceId
        }).lean();

        // Get geo location
        let location = null;
        if (session.ipAddress) {
          const geo = geoip.lookup(session.ipAddress);
          if (geo) {
            location = {
              country: geo.country,
              city: geo.city,
              lat: geo.ll[0],
              lon: geo.ll[1]
            };

            // Count by country
            sessionsData.geoDistribution[geo.country] = 
              (sessionsData.geoDistribution[geo.country] || 0) + 1;
          }
        }

        // Get trust score from Redis
        const trustKey = `trust:${user._id}:${session.deviceId}`;
        const trustData = await redis.get(trustKey);
        let trustScore = 50;
        let trustLevel = "MEDIUM";

        if (trustData) {
          const parsed = JSON.parse(trustData);
          trustScore = parsed.score;
          trustLevel = parsed.factors ? getTrustLevel(parsed.score) : "MEDIUM";
        }

        sessionsData.byTrustLevel[trustLevel]++;

        // Build session object
        const sessionInfo = {
          userId: user._id.toString(),
          email: user.email,
          plan: user.plan,
          deviceId: session.deviceId,
          trustScore,
          trustLevel,
          location,
          lastActivity: session.lastActivity,
          createdAt: session.createdAt,
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          deviceInfo: device ? {
            trusted: device.trusted,
            firstSeen: device.createdAt
          } : null
        };

        sessionsData.activeSessions.push(sessionInfo);

        // Recent activity (last 10 minutes)
        if (Date.now() - session.lastActivity < 10 * 60 * 1000) {
          sessionsData.recentActivity.push({
            email: user.email,
            action: "Active Session",
            deviceId: session.deviceId.substring(0, 8),
            timestamp: session.lastActivity,
            trustScore
          });
        }
      }
    }

    // Sort recent activity by timestamp
    sessionsData.recentActivity.sort((a, b) => b.timestamp - a.timestamp);
    sessionsData.recentActivity = sessionsData.recentActivity.slice(0, 20);

    // Calculate statistics
    const stats = await calculateStatistics(sessionsData);

    return {
      sessions: sessionsData,
      stats,
      timestamp: Date.now()
    };

  } catch (err) {
    console.error("Error getting dashboard data:", err);
    return {
      error: err.message,
      timestamp: Date.now()
    };
  }
}

function getTrustLevel(score) {
  if (score >= 80) return "HIGH";
  if (score >= 60) return "MEDIUM";
  if (score >= 40) return "LOW";
  return "CRITICAL";
}

async function calculateStatistics(sessionsData) {
  // Users statistics
  const totalUsers = await User.countDocuments();
  const activeUsers = new Set(
    sessionsData.activeSessions.map(s => s.userId)
  ).size;

  // Plan distribution
  const planStats = await User.aggregate([
    { $group: { _id: "$plan", count: { $sum: 1 } } }
  ]);

  // Trust score average
  const avgTrustScore = sessionsData.activeSessions.length > 0
    ? sessionsData.activeSessions.reduce((sum, s) => sum + s.trustScore, 0) / 
      sessionsData.activeSessions.length
    : 0;

  // Suspicious activity count (trust score < 40)
  const suspiciousCount = sessionsData.activeSessions.filter(
    s => s.trustScore < 40
  ).length;

  // Device sharing detection (multiple users per device)
  const deviceUserMap = {};
  for (const session of sessionsData.activeSessions) {
    if (!deviceUserMap[session.deviceId]) {
      deviceUserMap[session.deviceId] = new Set();
    }
    deviceUserMap[session.deviceId].add(session.userId);
  }
  
  const sharedDevices = Object.values(deviceUserMap).filter(
    users => users.size > 1
  ).length;

  // Revenue leakage estimation
  const potentialLeakage = calculateRevenueLeakage(sessionsData);

  return {
    totalUsers,
    activeUsers,
    totalSessions: sessionsData.totalSessions,
    avgTrustScore: Math.round(avgTrustScore),
    suspiciousCount,
    sharedDevices,
    planDistribution: planStats,
    revenueLeakage: potentialLeakage
  };
}

function calculateRevenueLeakage(sessionsData) {
  const planPrices = {
    BASIC: 199,
    STANDARD: 499,
    PREMIUM: 799
  };

  let estimatedLeakage = 0;

  // Group sessions by user
  const userSessions = {};
  for (const session of sessionsData.activeSessions) {
    if (!userSessions[session.userId]) {
      userSessions[session.userId] = {
        plan: session.plan,
        sessions: []
      };
    }
    userSessions[session.userId].sessions.push(session);
  }

  // Calculate leakage
  for (const userId in userSessions) {
    const { plan, sessions } = userSessions[userId];
    const maxAllowed = getMaxSessions(plan);
    
    if (sessions.length > maxAllowed) {
      const extraSessions = sessions.length - maxAllowed;
      // Assume each extra session represents a potential subscriber
      estimatedLeakage += planPrices[plan] * extraSessions;
    }

    // Check for suspicious patterns (low trust scores)
    const suspiciousSessions = sessions.filter(s => s.trustScore < 50);
    if (suspiciousSessions.length > 0) {
      estimatedLeakage += planPrices[plan] * 0.5 * suspiciousSessions.length;
    }
  }

  return Math.round(estimatedLeakage);
}

function getMaxSessions(plan) {
  if (plan === "BASIC") return 1;
  if (plan === "STANDARD") return 2;
  if (plan === "PREMIUM") return 4;
  return 1;
}

// Emit real-time events
function emitSessionEvent(event, data) {
  if (io) {
    io.emit(event, data);
  }
}

module.exports = {
  initializeSocket,
  getDashboardData,
  emitSessionEvent
};