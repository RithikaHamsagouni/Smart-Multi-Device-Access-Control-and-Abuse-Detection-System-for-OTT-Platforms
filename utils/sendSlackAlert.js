const axios = require("axios");

// Severity colors for Slack messages
const SEVERITY_COLORS = {
  CRITICAL: "#DC2626",
  HIGH: "#EA580C",
  MEDIUM: "#F59E0B",
  LOW: "#3B82F6"
};

const SEVERITY_EMOJIS = {
  CRITICAL: "🚨",
  HIGH: "⚠️",
  MEDIUM: "⚡",
  LOW: "ℹ️"
};

// Send alert to Slack
async function sendSlackAlert(alert, context) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;

  if (!webhookUrl) {
    console.warn("⚠️ Slack webhook URL not configured");
    return;
  }

  try {
    const payload = buildSlackPayload(alert, context);
    
    await axios.post(webhookUrl, payload, {
      headers: { "Content-Type": "application/json" }
    });

    console.log(`✅ Slack alert sent: ${alert.ruleName}`);
  } catch (err) {
    console.error("❌ Failed to send Slack alert:", err.message);
  }
}

// Build Slack message payload
function buildSlackPayload(alert, context) {
  const color = SEVERITY_COLORS[alert.severity];
  const emoji = SEVERITY_EMOJIS[alert.severity];

  return {
    username: "OTT Security Bot",
    icon_emoji: ":shield:",
    attachments: [
      {
        color: color,
        title: `${emoji} ${alert.ruleName}`,
        text: alert.message,
        fields: [
          {
            title: "Severity",
            value: alert.severity,
            short: true
          },
          {
            title: "User",
            value: context.email,
            short: true
          },
          {
            title: "IP Address",
            value: context.ipAddress || "Unknown",
            short: true
          },
          {
            title: "Location",
            value: context.location 
              ? `${context.location.city}, ${context.location.country}` 
              : "Unknown",
            short: true
          },
          ...(context.trustScore !== undefined ? [{
            title: "Trust Score",
            value: `${context.trustScore}/100`,
            short: true
          }] : []),
          {
            title: "Timestamp",
            value: new Date(alert.timestamp).toLocaleString(),
            short: true
          }
        ],
        footer: "OTT Security Alert System",
        footer_icon: "https://platform.slack-edge.com/img/default_application_icon.png",
        ts: Math.floor(alert.timestamp / 1000)
      }
    ],
    blocks: [
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*${emoji} Security Alert: ${alert.ruleName}*\n${alert.message}`
        }
      },
      {
        type: "divider"
      },
      {
        type: "section",
        fields: [
          {
            type: "mrkdwn",
            text: `*Severity:*\n${alert.severity}`
          },
          {
            type: "mrkdwn",
            text: `*User:*\n${context.email}`
          },
          {
            type: "mrkdwn",
            text: `*IP Address:*\n${context.ipAddress || "Unknown"}`
          },
          {
            type: "mrkdwn",
            text: `*Location:*\n${context.location ? `${context.location.city}, ${context.location.country}` : "Unknown"}`
          }
        ]
      },
      ...(context.trustScore !== undefined ? [{
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Trust Score:* ${context.trustScore}/100 ${getTrustScoreBar(context.trustScore)}`
        }
      }] : []),
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: {
              type: "plain_text",
              text: "View Dashboard"
            },
            url: process.env.ADMIN_DASHBOARD_URL || "http://localhost:5000/admin",
            style: "primary"
          },
          {
            type: "button",
            text: {
              type: "plain_text",
              text: "Block User"
            },
            url: `${process.env.ADMIN_DASHBOARD_URL || "http://localhost:5000/admin"}?action=block&userId=${context.userId}`,
            style: "danger"
          }
        ]
      }
    ]
  };
}

// Generate visual trust score bar
function getTrustScoreBar(score) {
  const filled = Math.floor(score / 10);
  const empty = 10 - filled;
  return "█".repeat(filled) + "░".repeat(empty);
}

// Send alert to Discord
async function sendDiscordAlert(alert, context) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl) {
    console.warn("⚠️ Discord webhook URL not configured");
    return;
  }

  try {
    const payload = buildDiscordPayload(alert, context);
    
    await axios.post(webhookUrl, payload, {
      headers: { "Content-Type": "application/json" }
    });

    console.log(`✅ Discord alert sent: ${alert.ruleName}`);
  } catch (err) {
    console.error("❌ Failed to send Discord alert:", err.message);
  }
}

// Build Discord embed payload
function buildDiscordPayload(alert, context) {
  const color = parseInt(SEVERITY_COLORS[alert.severity].replace("#", ""), 16);
  const emoji = SEVERITY_EMOJIS[alert.severity];

  return {
    username: "OTT Security Bot",
    avatar_url: "https://cdn-icons-png.flaticon.com/512/2913/2913133.png",
    embeds: [
      {
        title: `${emoji} ${alert.ruleName}`,
        description: alert.message,
        color: color,
        fields: [
          {
            name: "Severity",
            value: alert.severity,
            inline: true
          },
          {
            name: "User",
            value: context.email,
            inline: true
          },
          {
            name: "IP Address",
            value: context.ipAddress || "Unknown",
            inline: true
          },
          {
            name: "Location",
            value: context.location 
              ? `${context.location.city}, ${context.location.country}` 
              : "Unknown",
            inline: true
          },
          ...(context.trustScore !== undefined ? [{
            name: "Trust Score",
            value: `${context.trustScore}/100`,
            inline: true
          }] : [])
        ],
        footer: {
          text: "OTT Security Alert System"
        },
        timestamp: new Date(alert.timestamp).toISOString()
      }
    ],
    components: [
      {
        type: 1,
        components: [
          {
            type: 2,
            style: 5,
            label: "View Dashboard",
            url: process.env.ADMIN_DASHBOARD_URL || "http://localhost:5000/admin"
          }
        ]
      }
    ]
  };
}

// Send to custom webhook
async function sendCustomWebhook(alert, context) {
  const webhookUrl = process.env.CUSTOM_WEBHOOK_URL;

  if (!webhookUrl) {
    return;
  }

  try {
    const payload = {
      alert: {
        id: alert.ruleId,
        name: alert.ruleName,
        severity: alert.severity,
        message: alert.message,
        timestamp: alert.timestamp
      },
      context: {
        userId: context.userId,
        email: context.email,
        deviceId: context.deviceId,
        ipAddress: context.ipAddress,
        location: context.location,
        trustScore: context.trustScore
      }
    };

    await axios.post(webhookUrl, payload, {
      headers: { 
        "Content-Type": "application/json",
        "X-Alert-Signature": generateSignature(payload)
      }
    });

    console.log(`✅ Custom webhook sent: ${alert.ruleName}`);
  } catch (err) {
    console.error("❌ Failed to send custom webhook:", err.message);
  }
}

// Generate HMAC signature for webhook security
function generateSignature(payload) {
  const crypto = require("crypto");
  const secret = process.env.WEBHOOK_SECRET || "default_secret";
  
  return crypto
    .createHmac("sha256", secret)
    .update(JSON.stringify(payload))
    .digest("hex");
}

module.exports = sendSlackAlert;
module.exports.sendDiscordAlert = sendDiscordAlert;
module.exports.sendCustomWebhook = sendCustomWebhook;