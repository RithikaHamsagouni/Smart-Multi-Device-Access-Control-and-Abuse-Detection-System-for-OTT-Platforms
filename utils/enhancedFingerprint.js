const crypto = require("crypto");
const UAParser = require("ua-parser-js");

/**
 * Generate enhanced device fingerprint
 * Combines multiple factors to create a unique, harder-to-spoof device ID
 */
function generateEnhancedFingerprint(req, clientFingerprint = {}) {
  const parser = new UAParser(req.headers["user-agent"]);
  const ua = parser.getResult();

  // Collect fingerprint components
  const components = {
    // Basic identifiers
    userAgent: req.headers["user-agent"] || "",
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "",
    
    // Browser details
    browser: ua.browser.name || "",
    browserVersion: ua.browser.version || "",
    engine: ua.engine.name || "",
    
    // OS details
    os: ua.os.name || "",
    osVersion: ua.os.version || "",
    
    // Device details
    deviceType: ua.device.type || "desktop",
    deviceVendor: ua.device.vendor || "",
    deviceModel: ua.device.model || "",
    
    // CPU architecture
    cpu: ua.cpu.architecture || "",
    
    // Headers
    acceptLanguage: req.headers["accept-language"] || "",
    acceptEncoding: req.headers["accept-encoding"] || "",
    accept: req.headers["accept"] || "",
    
    // Client-provided fingerprint (from browser)
    // These should be collected via JavaScript on client-side
    screenResolution: clientFingerprint.screenResolution || "",
    timezone: clientFingerprint.timezone || "",
    timezoneOffset: clientFingerprint.timezoneOffset || "",
    canvas: clientFingerprint.canvas || "",
    webgl: clientFingerprint.webgl || "",
    fonts: clientFingerprint.fonts || "",
    plugins: clientFingerprint.plugins || "",
    audioContext: clientFingerprint.audioContext || "",
    platform: clientFingerprint.platform || "",
    hardwareConcurrency: clientFingerprint.hardwareConcurrency || "",
    deviceMemory: clientFingerprint.deviceMemory || "",
    colorDepth: clientFingerprint.colorDepth || "",
    pixelRatio: clientFingerprint.pixelRatio || ""
  };

  // Create stable fingerprint string
  const fingerprintString = Object.entries(components)
    .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
    .map(([key, value]) => `${key}:${value}`)
    .join("|");

  // Generate SHA-256 hash
  const deviceId = crypto
    .createHash("sha256")
    .update(fingerprintString)
    .digest("hex");

  return {
    deviceId,
    components,
    metadata: {
      browserInfo: `${ua.browser.name} ${ua.browser.version}`,
      osInfo: `${ua.os.name} ${ua.os.version}`,
      deviceInfo: ua.device.type || "desktop",
      timestamp: Date.now()
    }
  };
}

/**
 * Calculate fingerprint stability score
 * Higher score = more stable/reliable fingerprint
 */
function calculateStabilityScore(components) {
  let score = 0;
  
  // Client-side fingerprints are most stable
  if (components.canvas) score += 20;
  if (components.webgl) score += 20;
  if (components.fonts) score += 15;
  if (components.audioContext) score += 10;
  
  // Browser info is relatively stable
  if (components.browser && components.browserVersion) score += 10;
  
  // OS info is stable
  if (components.os && components.osVersion) score += 10;
  
  // Hardware info is very stable
  if (components.screenResolution) score += 10;
  if (components.hardwareConcurrency) score += 5;
  
  return Math.min(100, score);
}

/**
 * Detect if fingerprint components suggest spoofing/automation
 */
function detectSpoofing(components) {
  const warnings = [];
  let riskScore = 0;

  // Check for missing expected properties
  if (!components.userAgent || components.userAgent.length < 20) {
    warnings.push("Suspicious user agent");
    riskScore += 30;
  }

  // Check for automation tools
  const automationSignals = [
    "headless", "phantom", "selenium", "webdriver", 
    "puppeteer", "playwright", "automation"
  ];
  
  const uaLower = components.userAgent.toLowerCase();
  for (const signal of automationSignals) {
    if (uaLower.includes(signal)) {
      warnings.push(`Automation detected: ${signal}`);
      riskScore += 50;
    }
  }

  // Check for inconsistencies
  if (components.platform && components.os) {
    const platform = components.platform.toLowerCase();
    const os = components.os.toLowerCase();
    
    if ((platform.includes("win") && !os.includes("windows")) ||
        (platform.includes("mac") && !os.includes("mac")) ||
        (platform.includes("linux") && !os.includes("linux"))) {
      warnings.push("Platform-OS mismatch");
      riskScore += 25;
    }
  }

  // Check for missing client-side fingerprint
  if (!components.canvas && !components.webgl && !components.fonts) {
    warnings.push("No client-side fingerprint provided");
    riskScore += 40;
  }

  return {
    isSuspicious: riskScore > 50,
    riskScore: Math.min(100, riskScore),
    warnings
  };
}

/**
 * Compare two fingerprints to detect changes
 */
function compareFingerprints(oldComponents, newComponents) {
  const changes = [];
  const criticalKeys = [
    "browser", "os", "deviceType", "screenResolution", 
    "canvas", "webgl", "hardwareConcurrency"
  ];

  for (const key of criticalKeys) {
    if (oldComponents[key] && newComponents[key] && 
        oldComponents[key] !== newComponents[key]) {
      changes.push({
        field: key,
        oldValue: oldComponents[key],
        newValue: newComponents[key]
      });
    }
  }

  return {
    hasChanges: changes.length > 0,
    changes,
    changeCount: changes.length,
    suspicionLevel: changes.length >= 3 ? "HIGH" : changes.length >= 1 ? "MEDIUM" : "LOW"
  };
}

module.exports = {
  generateEnhancedFingerprint,
  calculateStabilityScore,
  detectSpoofing,
  compareFingerprints
};