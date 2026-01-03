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

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     tags: [Authentication]
 *     summary: Register a new user
 *     description: Create a new user account with email and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 minLength: 8
 *                 example: SecurePass123!
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User created successfully
 *                 email:
 *                   type: string
 *                   example: user@example.com
 *       400:
 *         description: User already exists
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Rate limit exceeded (3 signups per hour)
 */
router.post("/signup", signupLimiter, authController.signup);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     tags: [Authentication]
 *     summary: Login user
 *     description: |
 *       Authenticate user and create session. Features include:
 *       - Enhanced device fingerprinting
 *       - Geo-impossibility detection
 *       - Device trust scoring (0-100)
 *       - Automated security alerts
 *       - Session limit enforcement
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 format: password
 *                 example: SecurePass123!
 *               fingerprint:
 *                 type: object
 *                 description: Browser fingerprint data (optional but recommended)
 *                 properties:
 *                   screenResolution:
 *                     type: string
 *                     example: "1920x1080"
 *                   timezone:
 *                     type: string
 *                     example: "Asia/Kolkata"
 *                   canvas:
 *                     type: string
 *                     example: "abc123hash..."
 *                   webgl:
 *                     type: object
 *                   fonts:
 *                     type: string
 *     responses:
 *       200:
 *         description: Login successful or OTP required
 *         content:
 *           application/json:
 *             schema:
 *               oneOf:
 *                 - type: object
 *                   properties:
 *                     token:
 *                       type: string
 *                       example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                     message:
 *                       type: string
 *                       example: Login successful
 *                     deviceId:
 *                       type: string
 *                     trustScore:
 *                       $ref: '#/components/schemas/TrustScore'
 *                     activeSessions:
 *                       type: number
 *                       example: 2
 *                     maxSessions:
 *                       type: number
 *                       example: 2
 *                 - type: object
 *                   properties:
 *                     message:
 *                       type: string
 *                       example: New device detected. OTP sent to email.
 *                     otpRequired:
 *                       type: boolean
 *                       example: true
 *                     trustScore:
 *                       type: number
 *                       example: 45
 *       400:
 *         description: Invalid credentials
 *       403:
 *         description: Suspicious activity detected
 *       429:
 *         description: Rate limit exceeded (5 attempts per 15 minutes)
 */
router.post(
  "/login",
  loginLimiter,
  checkBlockedMiddleware,
  authController.login
);

/**
 * @swagger
 * /api/auth/verify-otp:
 *   post:
 *     tags: [Authentication]
 *     summary: Verify OTP for new device
 *     description: Verify OTP sent to email when logging in from a new device
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - otp
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 example: user@example.com
 *               otp:
 *                 type: string
 *                 example: "123456"
 *               fingerprint:
 *                 type: object
 *                 description: Browser fingerprint data
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: OTP verified. Device approved. Please login again.
 *                 deviceId:
 *                   type: string
 *       400:
 *         description: Invalid or expired OTP
 *       429:
 *         description: Too many verification attempts
 */
router.post(
  "/verify-otp",
  otpVerifyLimiter,
  checkBlockedMiddleware,
  authController.verifyOtp
);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     tags: [Authentication]
 *     summary: Logout user
 *     description: Terminate current session and invalidate JWT token
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Logged out successfully
 *       401:
 *         description: Unauthorized - Invalid or missing token
 */
router.post("/logout", authMiddleware, authController.logout);

/**
 * @swagger
 * /api/auth/sessions:
 *   get:
 *     tags: [Sessions]
 *     summary: Get all active sessions
 *     description: Retrieve all active sessions for the authenticated user
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of active sessions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 sessions:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Session'
 *                 total:
 *                   type: number
 *                   example: 2
 *                 maxAllowed:
 *                   type: number
 *                   example: 2
 *       401:
 *         description: Unauthorized
 */
router.get("/sessions", authMiddleware, authController.getSessions);

/**
 * @swagger
 * /api/auth/sessions/{deviceId}:
 *   delete:
 *     tags: [Sessions]
 *     summary: Terminate specific session
 *     description: Force logout a specific device session (cannot terminate current session)
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: deviceId
 *         required: true
 *         schema:
 *           type: string
 *         description: Device ID of the session to terminate
 *     responses:
 *       200:
 *         description: Session terminated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Session terminated successfully
 *                 deviceId:
 *                   type: string
 *       400:
 *         description: Cannot terminate current session or invalid device ID
 *       401:
 *         description: Unauthorized
 */
router.delete(
  "/sessions/:deviceId",
  authMiddleware,
  authController.terminateSession
);

module.exports = router;