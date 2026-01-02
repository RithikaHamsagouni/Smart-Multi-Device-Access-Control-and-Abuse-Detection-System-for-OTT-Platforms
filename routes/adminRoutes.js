const express = require("express");
const router = express.Router();
const { getDashboardData } = require("../config/socket");
const { sessionHelpers, redis } = require("../config/redis");
const User = require("../models/User");
const Device = require("../models/Device");
const Session = require("../models/Session");

// Simple admin auth middleware (you should replace with proper authentication)
const adminAuth = (req, res, next) => {
  const adminKey = req.headers["x-admin-key"];
  
  if (adminKey !== process.env.ADMIN_SECRET_KEY) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  
  next();
};

// Get dashboard data
router.get("/dashboard", adminAuth, async (req, res) => {
  try {
    const data = await getDashboardData();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get user details with all sessions
router.get("/users/:userId", adminAuth, async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const sessions = await sessionHelpers.getUserSessions(user._id);
    const devices = await Device.find({ userId: user._id });

    // Get location history
    const locationHistory = await redis.lrange(
      `user:${user._id}:location_history`,
      0,
      49
    );

    res.json({
      user: {
        id: user._id,
        email: user.email,
        plan: user.plan,
        createdAt: user.createdAt
      },
      sessions: sessions.map(s => ({
        deviceId: s.deviceId,
        createdAt: new Date(s.createdAt),
        lastActivity: new Date(s.lastActivity),
        trustScore: s.trustScore
      })),
      devices: devices.map(d => ({
        deviceId: d.deviceId,
        trusted: d.trusted,
        firstSeen: d.createdAt,
        lastLogin: d.lastLogin
      })),
      locationHistory: locationHistory.map(l => JSON.parse(l))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Force terminate user session
router.post("/sessions/terminate", adminAuth, async (req, res) => {
  try {
    const { userId, deviceId } = req.body;

    await sessionHelpers.deleteSession(userId, deviceId);
    await Session.updateOne(
      { userId, deviceId },
      { isActive: false }
    );

    res.json({ message: "Session terminated", userId, deviceId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Block user temporarily
router.post("/users/block", adminAuth, async (req, res) => {
  try {
    const { userId, duration = 3600 } = req.body;

    await redis.setex(`blocked:${userId}`, duration, "1");

    // Terminate all active sessions
    const sessions = await sessionHelpers.getUserSessions(userId);
    for (const session of sessions) {
      await sessionHelpers.deleteSession(userId, session.deviceId);
    }

    res.json({
      message: "User blocked",
      userId,
      duration,
      expiresAt: Date.now() + duration * 1000
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get suspicious activity report
router.get("/reports/suspicious", adminAuth, async (req, res) => {
  try {
    const data = await getDashboardData();
    const suspicious = data.sessions.activeSessions.filter(
      s => s.trustScore < 50
    );

    // Group by reason
    const report = {
      total: suspicious.length,
      byTrustLevel: {},
      users: suspicious.map(s => ({
        email: s.email,
        deviceId: s.deviceId.substring(0, 8),
        trustScore: s.trustScore,
        location: s.location,
        lastActivity: new Date(s.lastActivity)
      }))
    };

    res.json(report);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get revenue leakage report
router.get("/reports/revenue-leakage", adminAuth, async (req, res) => {
  try {
    const data = await getDashboardData();
    
    res.json({
      totalLeakage: data.stats.revenueLeakage,
      sharedDevices: data.stats.sharedDevices,
      suspiciousAccounts: data.stats.suspiciousCount,
      recommendations: [
        "Monitor accounts with trust scores below 40",
        `${data.stats.sharedDevices} devices are being shared across accounts`,
        "Consider enforcing stricter device limits for BASIC plan users"
      ]
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Analytics - Sessions over time
router.get("/analytics/sessions-timeline", adminAuth, async (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const timeline = [];

    // Get session creation data from MongoDB
    const startTime = new Date(Date.now() - hours * 60 * 60 * 1000);
    
    const sessions = await Session.aggregate([
      {
        $match: {
          createdAt: { $gte: startTime }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: {
              format: "%Y-%m-%d %H:00",
              date: "$createdAt"
            }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.json({
      timeline: sessions.map(s => ({
        time: s._id,
        count: s.count
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;