const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Device = require("../models/Device");
const Session = require("../models/Session");

// Redis & Utils
const { sessionHelpers, redis } = require("../config/redis");
const { checkGeoImpossibility, storeLocationHistory } = require("../utils/geoDetection");
const deviceTrustScorer = require("../utils/deviceTrustScoring");
const { generateEnhancedFingerprint, detectSpoofing } = require("../utils/enhancedFingerprint");
const generateOTP = require("../utils/generateOTP");
const sendOTPEmail = require("../utils/sendOTPEmail");
const { blockUser } = require("../middleware/rateLimiter");
const alertRulesEngine = require("../utils/alertRulesEngine");

const getMaxSessions = (plan) => {
  if (plan === "BASIC") return 1;
  if (plan === "STANDARD") return 2;
  if (plan === "PREMIUM") return 4;
  return 1;
};

// SIGNUP
exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashedPassword });

    res.status(201).json({ 
      message: "User created successfully",
      email: user.email 
    });
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
};

// LOGIN with Enhanced Security
exports.login = async (req, res) => {
  const { email, password, fingerprint } = req.body;

  try {
    // 1. Validate user credentials
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    // 2. Generate enhanced device fingerprint
    const { deviceId, components, metadata } = generateEnhancedFingerprint(req, fingerprint);

    // 3. Detect spoofing/automation
    const spoofingCheck = detectSpoofing(components);
    if (spoofingCheck.isSuspicious && spoofingCheck.riskScore > 70) {
      console.warn(`⚠️ Suspicious login detected for ${email}:`, spoofingCheck.warnings);
      
      // Block highly suspicious attempts
      await blockUser(user._id, 3600); // 1 hour block
      
      return res.status(403).json({
        error: "Suspicious activity detected",
        message: "Your login attempt has been flagged for security review.",
        warnings: spoofingCheck.warnings
      });
    }

    // 4. Check geo-impossibility
    const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const geoCheck = await checkGeoImpossibility(user._id, ipAddress);
    
    // Evaluate alert rules
    const alertContext = {
      userId: user._id,
      email: user.email,
      deviceId,
      ipAddress,
      geoCheck,
      trustScore: 50, // Will be updated later
      location: geoCheck.currentLocation,
      isNewDevice: false
    };
    
    if (geoCheck.isImpossible) {
      console.warn(`🌍 Geo-impossibility detected for ${email}:`, geoCheck.reason);
      
      // Trigger alert
      await alertRulesEngine.evaluateRules(alertContext);
      
      // Force OTP verification for impossible travel
      const otp = generateOTP();
      user.otp = otp;
      user.otpExpiry = Date.now() + 5 * 60 * 1000;
      await user.save();
      
      await sendOTPEmail(user.email, otp);
      
      return res.status(200).json({
        message: "Unusual location detected. OTP sent to email.",
        otpRequired: true,
        reason: geoCheck.reason,
        securityAlert: true
      });
    }

    // 5. Calculate device trust score
    const trustScore = await deviceTrustScorer.calculateTrustScore(
      user._id, 
      deviceId, 
      ipAddress
    );

    console.log(`🎯 Trust Score for ${email}: ${trustScore.score}/100 (${trustScore.level})`);

    // Update alert context with trust score
    alertContext.trustScore = trustScore.score;
    alertContext.isNewDevice = !device;
    
    // Check device sharing
    const deviceUserKey = `device:${deviceId}:users`;
    const deviceUserCount = await redis.scard(deviceUserKey);
    alertContext.deviceUserCount = deviceUserCount;

    // 6. Check if device exists
    let device = await Device.findOne({ userId: user._id, deviceId });

    if (!device) {
      alertContext.isNewDevice = true;
      
      // Trigger alert for new device if trust is low
      await alertRulesEngine.evaluateRules(alertContext);
      
      // New device - require OTP if trust score is low
      if (trustScore.score < 60) {
        const otp = generateOTP();
        user.otp = otp;
        user.otpExpiry = Date.now() + 5 * 60 * 1000;
        await user.save();

        await sendOTPEmail(user.email, otp);

        return res.status(200).json({
          message: "New device detected. OTP sent to email.",
          otpRequired: true,
          trustScore: trustScore.score,
          trustLevel: trustScore.level
        });
      }

      // High trust score - auto-approve device
      device = await Device.create({
        userId: user._id,
        deviceId,
        userAgent: req.headers["user-agent"],
        ipAddress,
        trusted: true
      });
    }

    // Evaluate all alert rules
    await alertRulesEngine.evaluateRules(alertContext);

    // 7. Update device last login
    device.lastLogin = new Date();
    await device.save();

    // 8. Track device usage
    await deviceTrustScorer.incrementLoginCount(deviceId);
    await deviceTrustScorer.trackDeviceUser(deviceId, user._id);
    await storeLocationHistory(user._id, ipAddress, deviceId);

    // 9. Check active sessions and enforce limits
    const activeSessions = await sessionHelpers.getUserSessions(user._id);
    const maxSessions = getMaxSessions(user.plan);

    if (activeSessions.length >= maxSessions) {
      // Force logout oldest session
      const oldestSession = activeSessions[0];
      console.log(`🚨 Force logging out session: ${oldestSession.deviceId}`);
      
      await sessionHelpers.deleteSession(user._id, oldestSession.deviceId);
      
      // Also mark MongoDB session as inactive (for backward compatibility)
      await Session.updateOne(
        { userId: user._id, deviceId: oldestSession.deviceId },
        { isActive: false }
      );
    }

    // 10. Create JWT token
    const token = jwt.sign(
      { userId: user._id, deviceId, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // 11. Create session in Redis
    await sessionHelpers.createSession(user._id, deviceId, token, {
      ipAddress,
      userAgent: req.headers["user-agent"],
      trustScore: trustScore.score,
      location: geoCheck.currentLocation
    });

    // 12. Also store in MongoDB (for analytics/backup)
    await Session.create({
      userId: user._id,
      deviceId,
      token
    });

    res.json({
      token,
      message: "Login successful",
      deviceId,
      trustScore: {
        score: trustScore.score,
        level: trustScore.level
      },
      activeSessions: activeSessions.length + 1,
      maxSessions,
      metadata: {
        browser: metadata.browserInfo,
        os: metadata.osInfo,
        device: metadata.deviceInfo
      }
    });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Login failed", details: err.message });
  }
};

// VERIFY OTP
exports.verifyOtp = async (req, res) => {
  const { email, otp, fingerprint } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    // Validate OTP
    if (user.otp !== otp || user.otpExpiry < Date.now()) {
      // Record failed attempt
      const { deviceId } = generateEnhancedFingerprint(req, fingerprint);
      await deviceTrustScorer.recordFailedAttempt(deviceId);
      
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    // Generate device fingerprint
    const { deviceId, components } = generateEnhancedFingerprint(req, fingerprint);
    const ipAddress = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

    // Create trusted device
    await Device.create({
      userId: user._id,
      deviceId,
      userAgent: req.headers["user-agent"],
      ipAddress,
      trusted: true
    });

    // Clear OTP
    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    // Track device
    await deviceTrustScorer.incrementLoginCount(deviceId);
    await deviceTrustScorer.trackDeviceUser(deviceId, user._id);

    res.json({ 
      message: "OTP verified. Device approved. Please login again.",
      deviceId 
    });

  } catch (err) {
    console.error("OTP verification error:", err);
    res.status(500).json({ message: "Verification failed" });
  }
};

// LOGOUT
exports.logout = async (req, res) => {
  try {
    const { userId, deviceId } = req.user;

    // Delete session from Redis
    await sessionHelpers.deleteSession(userId, deviceId);

    // Mark MongoDB session as inactive
    await Session.updateOne(
      { userId, deviceId, isActive: true },
      { isActive: false }
    );

    res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ error: "Logout failed" });
  }
};

// GET ALL SESSIONS (for user management)
exports.getSessions = async (req, res) => {
  try {
    const { userId } = req.user;

    const sessions = await sessionHelpers.getUserSessions(userId);
    
    // Enrich with device info
    const enrichedSessions = await Promise.all(
      sessions.map(async (session) => {
        const device = await Device.findOne({ 
          userId, 
          deviceId: session.deviceId 
        });

        return {
          deviceId: session.deviceId,
          createdAt: new Date(session.createdAt),
          lastActivity: new Date(session.lastActivity),
          ipAddress: session.ipAddress,
          userAgent: session.userAgent,
          trustScore: session.trustScore,
          location: session.location,
          isCurrent: session.deviceId === req.user.deviceId,
          deviceInfo: device ? {
            trusted: device.trusted,
            firstSeen: device.createdAt
          } : null
        };
      })
    );

    res.json({
      sessions: enrichedSessions,
      total: enrichedSessions.length,
      maxAllowed: getMaxSessions(req.user.plan || "BASIC")
    });

  } catch (err) {
    console.error("Get sessions error:", err);
    res.status(500).json({ error: "Failed to fetch sessions" });
  }
};

// TERMINATE SPECIFIC SESSION
exports.terminateSession = async (req, res) => {
  try {
    const { userId } = req.user;
    const { deviceId } = req.params;

    if (!deviceId) {
      return res.status(400).json({ error: "Device ID required" });
    }

    // Don't allow terminating current session
    if (deviceId === req.user.deviceId) {
      return res.status(400).json({ 
        error: "Cannot terminate current session. Use logout instead." 
      });
    }

    await sessionHelpers.deleteSession(userId, deviceId);
    await Session.updateOne(
      { userId, deviceId },
      { isActive: false }
    );

    res.json({ 
      message: "Session terminated successfully",
      deviceId 
    });

  } catch (err) {
    console.error("Terminate session error:", err);
    res.status(500).json({ error: "Failed to terminate session" });
  }
};

module.exports = exports;