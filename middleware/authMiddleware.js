const jwt = require("jsonwebtoken");
const { sessionHelpers } = require("../config/redis");
const { checkUserBlocked } = require("./rateLimiter");

module.exports = async (req, res, next) => {
  try {
    // 1. Check for authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Invalid token format" });
    }

    // 2. Verify JWT token
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ 
          error: "Token expired",
          message: "Your session has expired. Please login again." 
        });
      }
      return res.status(401).json({ error: "Invalid token" });
    }

    // 3. Check if user is blocked
    const isBlocked = await checkUserBlocked(decoded.userId);
    if (isBlocked) {
      return res.status(403).json({
        error: "Account suspended",
        message: "Your account has been temporarily suspended due to suspicious activity."
      });
    }

    // 4. Validate session in Redis (fast lookup)
    const isValid = await sessionHelpers.validateSession(
      decoded.userId,
      decoded.deviceId,
      token
    );

    if (!isValid) {
      return res.status(401).json({
        error: "Session expired or logged out",
        message: "Your session is no longer active. Please login again."
      });
    }

    // 5. Update last activity timestamp
    await sessionHelpers.updateActivity(decoded.userId, decoded.deviceId);

    // 6. Attach user info to request
    req.user = {
      userId: decoded.userId,
      deviceId: decoded.deviceId,
      email: decoded.email
    };

    next();

  } catch (err) {
    console.error("Auth middleware error:", err);
    return res.status(500).json({ 
      error: "Authentication failed",
      message: "An error occurred during authentication." 
    });
  }
};