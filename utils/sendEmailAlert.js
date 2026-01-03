const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Alert email templates by severity
const getEmailTemplate = (alert, context) => {
  const severityColors = {
    CRITICAL: "#DC2626",
    HIGH: "#EA580C",
    MEDIUM: "#F59E0B",
    LOW: "#3B82F6"
  };

  const severityEmojis = {
    CRITICAL: "🚨",
    HIGH: "⚠️",
    MEDIUM: "⚡",
    LOW: "ℹ️"
  };

  const color = severityColors[alert.severity];
  const emoji = severityEmojis[alert.severity];

  return {
    subject: `${emoji} Security Alert: ${alert.ruleName}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          .header {
            background: ${color};
            color: white;
            padding: 30px;
            text-align: center;
          }
          .header h1 {
            margin: 0;
            font-size: 24px;
          }
          .content {
            padding: 30px;
          }
          .alert-box {
            background: #f9fafb;
            border-left: 4px solid ${color};
            padding: 15px;
            margin: 20px 0;
          }
          .details {
            background: #f3f4f6;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
          }
          .details-row {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #e5e7eb;
          }
          .details-row:last-child {
            border-bottom: none;
          }
          .label {
            font-weight: bold;
            color: #6b7280;
          }
          .value {
            color: #111827;
          }
          .button {
            display: inline-block;
            background: ${color};
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 4px;
            margin: 20px 0;
          }
          .footer {
            background: #f9fafb;
            padding: 20px;
            text-align: center;
            font-size: 12px;
            color: #6b7280;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${emoji} Security Alert</h1>
            <p style="margin: 10px 0 0 0; font-size: 14px;">
              Severity: ${alert.severity}
            </p>
          </div>
          
          <div class="content">
            <h2>${alert.ruleName}</h2>
            
            <div class="alert-box">
              <strong>Alert Message:</strong><br>
              ${alert.message}
            </div>

            <h3>Details</h3>
            <div class="details">
              <div class="details-row">
                <span class="label">User Email:</span>
                <span class="value">${context.email}</span>
              </div>
              <div class="details-row">
                <span class="label">Device ID:</span>
                <span class="value">${context.deviceId.substring(0, 16)}...</span>
              </div>
              <div class="details-row">
                <span class="label">IP Address:</span>
                <span class="value">${context.ipAddress}</span>
              </div>
              ${context.location ? `
              <div class="details-row">
                <span class="label">Location:</span>
                <span class="value">${context.location.city}, ${context.location.country}</span>
              </div>
              ` : ''}
              ${context.trustScore !== undefined ? `
              <div class="details-row">
                <span class="label">Trust Score:</span>
                <span class="value">${context.trustScore}/100</span>
              </div>
              ` : ''}
              <div class="details-row">
                <span class="label">Timestamp:</span>
                <span class="value">${new Date(alert.timestamp).toLocaleString()}</span>
              </div>
            </div>

            <center>
              <a href="${process.env.ADMIN_DASHBOARD_URL || 'http://localhost:5000/admin'}" class="button">
                View Dashboard
              </a>
            </center>

            <p style="color: #6b7280; font-size: 14px; margin-top: 30px;">
              <strong>What should you do?</strong><br>
              ${getRecommendation(alert.severity)}
            </p>
          </div>

          <div class="footer">
            <p>This is an automated security alert from your OTT Authentication System.</p>
            <p>If you believe this is a false positive, please review the alert in your admin dashboard.</p>
          </div>
        </div>
      </body>
      </html>
    `
  };
};

// Get recommendations based on severity
function getRecommendation(severity) {
  const recommendations = {
    CRITICAL: "⚠️ Immediate action required! Review this activity in your dashboard and consider blocking the user if suspicious.",
    HIGH: "⚡ This activity requires your attention. Please review the user's recent activity and take appropriate action.",
    MEDIUM: "💡 Monitor this user's activity. Consider reaching out to verify if this is legitimate behavior.",
    LOW: "ℹ️ This is informational. No immediate action required, but keep an eye on patterns."
  };

  return recommendations[severity] || "Review this alert in your dashboard.";
}

// Send email alert
async function sendEmailAlert(alert, context) {
  try {
    // Get admin email from environment or use default
    const adminEmail = process.env.ADMIN_EMAIL || process.env.EMAIL_USER;

    if (!adminEmail) {
      console.warn("⚠️ Admin email not configured, skipping email alert");
      return;
    }

    const template = getEmailTemplate(alert, context);

    await transporter.sendMail({
      from: `"OTT Security Alert" <${process.env.EMAIL_USER}>`,
      to: adminEmail,
      subject: template.subject,
      html: template.html
    });

    console.log(`✅ Email alert sent for: ${alert.ruleName}`);
  } catch (err) {
    console.error("❌ Failed to send email alert:", err.message);
  }
}

// Send alert to user (optional)
async function sendUserAlert(userEmail, alert, context) {
  try {
    const template = {
      subject: "🔒 Security Alert for Your Account",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 20px auto; padding: 20px; background: white; border-radius: 8px; }
            .header { background: #DC2626; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; }
            .content { padding: 20px; }
            .alert-box { background: #FEF2F2; border-left: 4px solid #DC2626; padding: 15px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🔒 Security Alert</h1>
            </div>
            <div class="content">
              <p>Hi,</p>
              <p>We detected unusual activity on your account:</p>
              <div class="alert-box">
                ${alert.message}
              </div>
              <p><strong>Details:</strong></p>
              <ul>
                <li>Time: ${new Date(alert.timestamp).toLocaleString()}</li>
                <li>IP Address: ${context.ipAddress}</li>
                ${context.location ? `<li>Location: ${context.location.city}, ${context.location.country}</li>` : ''}
              </ul>
              <p>If this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately.</p>
              <p>Stay safe,<br>Your OTT Security Team</p>
            </div>
          </div>
        </body>
        </html>
      `
    };

    await transporter.sendMail({
      from: `"OTT Security" <${process.env.EMAIL_USER}>`,
      to: userEmail,
      subject: template.subject,
      html: template.html
    });

    console.log(`✅ User alert sent to: ${userEmail}`);
  } catch (err) {
    console.error("❌ Failed to send user alert:", err.message);
  }
}

module.exports = sendEmailAlert;
module.exports.sendUserAlert = sendUserAlert;