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

  // DEVICE CHECK
  let device = await Device.findOne({ userId: user._id, deviceId });

  if (!device) {
    device = await Device.create({
      userId: user._id,
      deviceId,
      userAgent,
      ipAddress
    });
  } else {
    device.lastLogin = new Date();
    await device.save();
  }

  // ACTIVE SESSIONS
  const activeSessions = await Session.find({
    userId: user._id,
    isActive: true
  }).sort({ createdAt: 1 });

  const maxSessions = getMaxSessions(user.plan);

  // 🚨 FORCE LOGOUT LOGIC
  if (activeSessions.length >= maxSessions) {
    const oldestSession = activeSessions[0];
    oldestSession.isActive = false;
    await oldestSession.save();
  }

  // CREATE TOKEN
  const token = jwt.sign(
    { userId: user._id, deviceId },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

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
