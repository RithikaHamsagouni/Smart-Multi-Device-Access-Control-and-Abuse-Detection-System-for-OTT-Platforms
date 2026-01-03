const swaggerJsDoc = require("swagger-jsdoc");

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "OTT Authentication API",
      version: "2.0.0",
      description: "Production-grade OTT platform authentication system with advanced security features",
      contact: {
        name: "API Support",
        email: "support@ottplatform.com"
      },
      license: {
        name: "MIT",
        url: "https://opensource.org/licenses/MIT"
      }
    },
    servers: [
      {
        url: "http://localhost:5000",
        description: "Development server"
      },
      {
        url: "https://api.ottplatform.com",
        description: "Production server"
      }
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "Enter your JWT token"
        },
        AdminKey: {
          type: "apiKey",
          in: "header",
          name: "X-Admin-Key",
          description: "Admin secret key for dashboard access"
        }
      },
      schemas: {
        User: {
          type: "object",
          properties: {
            email: {
              type: "string",
              format: "email",
              example: "user@example.com"
            },
            plan: {
              type: "string",
              enum: ["BASIC", "STANDARD", "PREMIUM"],
              example: "STANDARD"
            },
            createdAt: {
              type: "string",
              format: "date-time"
            }
          }
        },
        Session: {
          type: "object",
          properties: {
            deviceId: {
              type: "string",
              example: "abc123def456..."
            },
            token: {
              type: "string",
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            },
            trustScore: {
              type: "number",
              minimum: 0,
              maximum: 100,
              example: 75
            },
            location: {
              type: "object",
              properties: {
                country: { type: "string", example: "IN" },
                city: { type: "string", example: "Mumbai" }
              }
            },
            createdAt: {
              type: "string",
              format: "date-time"
            },
            lastActivity: {
              type: "string",
              format: "date-time"
            }
          }
        },
        TrustScore: {
          type: "object",
          properties: {
            score: {
              type: "number",
              minimum: 0,
              maximum: 100,
              example: 72
            },
            level: {
              type: "string",
              enum: ["HIGH", "MEDIUM", "LOW", "CRITICAL"],
              example: "MEDIUM"
            },
            factors: {
              type: "array",
              items: {
                type: "object",
                properties: {
                  factor: { type: "string" },
                  score: { type: "number" }
                }
              }
            }
          }
        },
        Alert: {
          type: "object",
          properties: {
            ruleId: {
              type: "string",
              example: "geo_impossibility"
            },
            ruleName: {
              type: "string",
              example: "Geographic Impossibility Detected"
            },
            severity: {
              type: "string",
              enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
              example: "CRITICAL"
            },
            message: {
              type: "string",
              example: "User attempted login from impossible location"
            },
            timestamp: {
              type: "number",
              example: 1704297600000
            }
          }
        },
        Error: {
          type: "object",
          properties: {
            error: {
              type: "string",
              example: "Invalid credentials"
            },
            message: {
              type: "string",
              example: "The provided email or password is incorrect"
            }
          }
        }
      }
    },
    tags: [
      {
        name: "Authentication",
        description: "User authentication endpoints"
      },
      {
        name: "Sessions",
        description: "Session management endpoints"
      },
      {
        name: "Admin",
        description: "Admin dashboard and monitoring endpoints"
      },
      {
        name: "Alerts",
        description: "Security alert management"
      }
    ]
  },
  apis: ["./routes/*.js", "./controllers/*.js"]
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);

module.exports = swaggerDocs;