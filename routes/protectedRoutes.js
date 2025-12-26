const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const Session = require("../models/Session");

// Middleware: verify session
const verifySession = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

  const session = await Session.findOne({
  userId: decoded.userId,
  token,
  deviceId: decoded.deviceId,
  isActive: true
});

    if (!session) {
      return res.status(401).json({ message: "Session expired" });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// Protected API
router.get("/protected", verifySession, (req, res) => {
  res.json({
    message: "Access granted",
    userId: req.user.userId
  });
});

module.exports = router;
