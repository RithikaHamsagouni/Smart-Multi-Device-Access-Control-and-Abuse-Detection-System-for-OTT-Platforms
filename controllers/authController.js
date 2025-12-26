const getMaxSessions = (plan) => {
  if (plan === "BASIC") return 1;
  if (plan === "STANDARD") return 2;
  if (plan === "PREMIUM") return 4;
};
const Session = require("../models/Session");
const Device = require("../models/Device");
const generateDeviceId = require("../utils/generateDeviceId");
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sendOTPEmail = require("../utils/sendOTPEmail");


// SIGNUP
exports.signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ email, password: hashedPassword });

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    res.status(400).json({ error: "User already exists" });
  }
};


//LOGIN

exports.login = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  // DEVICE INFO
  const userAgent = req.headers["user-agent"];
  const ipAddress =
    req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  const deviceId = generateDeviceId(userAgent, ipAddress);

  const generateOTP = require("../utils/generateOTP");

// DEVICE CHECK
let device = await Device.findOne({ userId: user._id, deviceId });

if (!device) {
  const otp = generateOTP();

  user.otp = otp;
  user.otpExpiry = Date.now() + 5 * 60 * 1000;
  await user.save();

  await sendOTPEmail(user.email, otp);

  return res.status(200).json({
    message: "New device detected. OTP sent to email.",
    otpRequired: true
  });
}

// EXISTING DEVICE
device.lastLogin = new Date();
await device.save();


  // ACTIVE SESSIONS
  const activeSessions = await Session.find({
    userId: user._id,
    isActive: true
  }).sort({ createdAt: 1 });

  const maxSessions = getMaxSessions(user.plan);

  // 🚨 FORCE LOGOUT LOGIC
  if (activeSessions.length >= maxSessions) {
    const oldestSession = activeSessions[0];
    console.log("Force logging out session:", oldestSession._id);
    oldestSession.isActive = false;
    await oldestSession.save();
  }

  // CREATE TOKEN
  const token = jwt.sign(
    { userId: user._id, deviceId },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
console.log("Creating session for device:", deviceId);

  // CREATE SESSION
  await Session.create({
    userId: user._id,
    deviceId,
    token
  });

  res.json({
    token,
    message: "Login successful",
    deviceId
  });
};
exports.verifyOtp = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: "User not found" });

  if (
    user.otp !== req.body.otp ||
    user.otpExpiry < Date.now()
  ) {
    return res.status(400).json({ message: "Invalid or expired OTP" });
  }

  // DEVICE INFO
  const userAgent = req.headers["user-agent"];
  const ipAddress =
    req.headers["x-forwarded-for"] || req.socket.remoteAddress;

  const deviceId = generateDeviceId(userAgent, ipAddress);

  // CREATE DEVICE AFTER OTP
  await Device.create({
    userId: user._id,
    deviceId,
    userAgent,
    ipAddress
  });

  // CLEAR OTP
  user.otp = null;
  user.otpExpiry = null;
  await user.save();

  res.json({ message: "OTP verified. Device approved. Please login again." });
};
