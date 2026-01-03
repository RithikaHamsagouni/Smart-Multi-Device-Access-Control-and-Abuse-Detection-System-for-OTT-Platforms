require("dotenv").config();
const express = require("express");
const http = require("http");
const cors = require("cors");
const swaggerUi = require("swagger-ui-express");
const swaggerDocs = require("./config/swagger");

const connectDB = require("./config/db");
const { redis } = require("./config/redis");
const { initializeSocket } = require("./config/socket");

const authRoutes = require("./routes/authRoutes");
const protectedRoutes = require("./routes/protectedRoutes");
const adminRoutes = require("./routes/adminRoutes");
const { apiLimiter } = require("./middleware/rateLimiter");

const app = express();
const server = http.createServer(app);

// Initialize Socket.IO
const io = initializeSocket(server);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Swagger Documentation
if (process.env.API_DOCS_ENABLED === "true") {
  app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));
  console.log("📚 API Documentation available at: http://localhost:5000/api-docs");
}

// Apply global API rate limiter
app.use("/api", apiLimiter);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api", protectedRoutes);
app.use("/api/admin", adminRoutes);

// Health check endpoint
app.get("/health", async (req, res) => {
  try {
    await redis.ping();
    res.json({
      status: "healthy",
      mongodb: "connected",
      redis: "connected",
      socketio: "active",
      swagger: process.env.API_DOCS_ENABLED === "true",
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    res.status(503).json({
      status: "unhealthy",
      error: err.message
    });
  }
});

// Serve admin dashboard
app.get("/admin", (req, res) => {
  res.sendFile(__dirname + "/public/admin.html");
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? err.message : undefined
  });
});

// Initialize server
const PORT = process.env.PORT || 5000;

async function startServer() {
  try {
    await connectDB();
    await redis.ping();
    console.log("✅ Redis connection verified");
    
    server.listen(PORT, () => {
      console.log(`
╔═══════════════════════════════════════════╗
║   🚀 OTT Authentication System Started   ║
╠═══════════════════════════════════════════╣
║  Server:    http://localhost:${PORT}       ║
║  Health:    http://localhost:${PORT}/health║
║  Dashboard: http://localhost:${PORT}/admin ║
║  API Docs:  http://localhost:${PORT}/api-docs║
╚═══════════════════════════════════════════╝
      `);
    });
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  console.log("SIGTERM received, shutting down gracefully...");
  await redis.quit();
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", async () => {
  console.log("SIGINT received, shutting down gracefully...");
  await redis.quit();
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

startServer();