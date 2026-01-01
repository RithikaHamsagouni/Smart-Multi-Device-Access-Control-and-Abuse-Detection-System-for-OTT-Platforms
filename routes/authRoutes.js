const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const authMiddleware = require("../middleware/authMiddleware");

// Rate limiters
const {
  signupLimiter,
  loginLimiter,
  otpRequestLimiter,
  otpVerifyLimiter,
  checkBlockedMiddleware
} = require("../middleware/rateLimiter");

// Public routes with rate limiting
router.post("/signup", signupLimiter, authController.signup);

router.post(
  "/login",
  loginLimiter,
  checkBlockedMiddleware,
  authController.login
);

router.post(
  "/verify-otp",
  otpVerifyLimiter,
  checkBlockedMiddleware,
  authController.verifyOtp
);

// Protected routes (require authentication)
router.post("/logout", authMiddleware, authController.logout);

router.get("/sessions", authMiddleware, authController.getSessions);

router.delete(
  "/sessions/:deviceId",
  authMiddleware,
  authController.terminateSession
);

module.exports = router;