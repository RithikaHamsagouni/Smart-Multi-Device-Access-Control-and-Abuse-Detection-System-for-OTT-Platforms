const crypto = require("crypto");

const generateDeviceId = (userAgent, ip) => {
  return crypto
    .createHash("sha256")
    .update(userAgent + ip)
    .digest("hex");
};

module.exports = generateDeviceId;
