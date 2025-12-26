const express = require("express");
const router = express.Router();

const authController = require("../controllers/authController"); // ✅ ADD THIS

router.post("/signup", authController.signup);
router.post("/login", authController.login);
router.post("/verify-otp", authController.verifyOtp); // ✅ now works

module.exports = router;

