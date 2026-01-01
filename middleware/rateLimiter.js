const rateLimit = require("express-rate-limit");
const { redis } = require("../config/redis");

// Custom Redis store for rate limiting
class RedisStore {
  constructor(options) {
    this.prefix = options.prefix || "rl:";
    this.resetExpiryOnChange = options.resetExpiryOnChange || false;
  }

  async increment(key) {
    const fullKey = this.prefix + key;
    const current = await redis.incr(fullKey);
    
    if (current === 1) {
      await redis.expire(fullKey, 900); // 15 minutes
    }
    
    return {
      totalHits: current,
      resetTime: new Date(Date.now() + 900000)
    };
  }

  async decrement(key) {
    const fullKey = this.prefix + key;
    await redis.decr(fullKey);
  }

  async resetKey(key) {
    const fullKey = this.prefix + key;
    await redis.del(fullKey);
  }
}

// Login attempts rate limiter (5 attempts per 15 minutes per IP)
const loginLimiter = rateLimit({
  store: new RedisStore({ prefix: "rl:login:" }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: {
    error: "Too many login attempts. Please try again after 15 minutes."
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  },
  handler: (req, res) => {
    res.status(429).json({
      error: "Too many login attempts",
      retryAfter: "15 minutes",
      message: "Your account has been temporarily locked due to multiple failed login attempts."
    });
  }
});

// OTP request rate limiter (3 OTP requests per hour)
const otpRequestLimiter = rateLimit({
  store: new RedisStore({ prefix: "rl:otp:" }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: {
    error: "Too many OTP requests. Please try again after 1 hour."
  },
  keyGenerator: (req) => {
    return req.body.email || req.headers["x-forwarded-for"];
  },
  handler: (req, res) => {
    res.status(429).json({
      error: "OTP request limit exceeded",
      retryAfter: "1 hour",
      message: "You have requested too many OTPs. Please try again later."
    });
  }
});

// OTP verification rate limiter (5 attempts per OTP)
const otpVerifyLimiter = rateLimit({
  store: new RedisStore({ prefix: "rl:otp_verify:" }),
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5,
  message: {
    error: "Too many OTP verification attempts."
  },
  keyGenerator: (req) => {
    return req.body.email || "unknown";
  },
  handler: (req, res) => {
    res.status(429).json({
      error: "Too many failed OTP attempts",
      message: "Your OTP has been invalidated due to multiple failed attempts. Please request a new one."
    });
  }
});

// Signup rate limiter (3 signups per hour per IP)
const signupLimiter = rateLimit({
  store: new RedisStore({ prefix: "rl:signup:" }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: {
    error: "Too many signup attempts from this IP."
  },
  keyGenerator: (req) => {
    return req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  }
});

// API rate limiter (100 requests per minute per user)
const apiLimiter = rateLimit({
  store: new RedisStore({ prefix: "rl:api:" }),
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: {
    error: "Too many requests. Please slow down."
  },
  keyGenerator: (req) => {
    return req.user?.userId || req.headers["x-forwarded-for"];
  }
});

// Custom function to check if user should be temporarily blocked
async function checkUserBlocked(userId) {
  const key = `blocked:${userId}`;
  const isBlocked = await redis.get(key);
  return isBlocked === "1";
}

// Block user temporarily (after suspicious activity)
async function blockUser(userId, durationSeconds = 3600) {
  const key = `blocked:${userId}`;
  await redis.setex(key, durationSeconds, "1");
}

// Middleware to check if user is blocked
const checkBlockedMiddleware = async (req, res, next) => {
  if (!req.body.email && !req.user?.userId) {
    return next();
  }

  const User = require("../models/User");
  let userId;

  if (req.body.email) {
    const user = await User.findOne({ email: req.body.email });
    userId = user?._id;
  } else {
    userId = req.user?.userId;
  }

  if (userId && await checkUserBlocked(userId)) {
    return res.status(403).json({
      error: "Account temporarily suspended",
      message: "Your account has been temporarily suspended due to suspicious activity. Please try again later or contact support."
    });
  }

  next();
};

module.exports = {
  loginLimiter,
  otpRequestLimiter,
  otpVerifyLimiter,
  signupLimiter,
  apiLimiter,
  checkBlockedMiddleware,
  blockUser,
  checkUserBlocked
};