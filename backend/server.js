const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
require("dotenv").config();

const scanRoutes = require("./routes/xssRoutes");
const demoRoutes = require("./routes/demoRoutes");
const authRoutes = require("./routes/authRoutes");

const app = express();

// CORS configuration supporting deployed frontends
const clientUrl = process.env.CLIENT_URL;
app.use(
  cors({
    origin: clientUrl && clientUrl !== "*" ? [clientUrl, "http://localhost:5173", "http://localhost:3000"] : "*",
    credentials: true
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB connection
const mongoUri = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/xssScannerDB";
mongoose
  .connect(mongoUri)
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((error) => {
    console.log("MongoDB connection error:", error.message);
  });

// API Routes
app.use("/api/auth", authRoutes);
app.use("/api/scan", scanRoutes);
app.use("/demo", demoRoutes);

// Health check endpoint for deployment monitoring
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    service: "xss-scanner-backend",
    timestamp: new Date().toISOString()
  });
});

// Serve frontend build if available (supports single-service full-stack deployment)
const frontendDistPath = path.join(__dirname, "../frontend/dist");
app.use(express.static(frontendDistPath));

app.get("/", (req, res) => {
  const indexPath = path.join(frontendDistPath, "index.html");
  const fs = require("fs");
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  res.send("XSS Scanner Backend Running");
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});