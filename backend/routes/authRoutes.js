const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("../models/User");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "xss_scanner_super_secret_jwt_key_2026";

// Generate JWT Helper
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
};

// 1. REGISTER USER
// Validates, saves to MongoDB, then verifies immediate MongoDB persistence
router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide name, email, and password."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters long."
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "An account with this email address already exists."
      });
    }

    const newUser = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: password
    });

    const savedUser = await newUser.save();

    const verificationRecord = await User.findById(savedUser._id)
      .select("-password")
      .lean();

    if (!verificationRecord) {
      return res.status(500).json({
        success: false,
        verifiedInDb: false,
        message: "User was saved but could not be verified in MongoDB."
      });
    }

    const dbAudit = {
      verified: true,
      databaseName: mongoose.connection.name || "xssScannerDB",
      collectionName: User.collection.collectionName || "users",
      documentId: verificationRecord._id.toString(),
      storedName: verificationRecord.name,
      storedEmail: verificationRecord.email,
      storedAt: verificationRecord.createdAt,
      readyState: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected"
    };

    const token = generateToken(verificationRecord);

    return res.status(201).json({
      success: true,
      message: "Registration successful! User verified and stored in MongoDB.",
      verifiedInDb: true,
      dbAudit,
      user: {
        id: verificationRecord._id,
        name: verificationRecord.name,
        email: verificationRecord.email,
        role: verificationRecord.role,
        createdAt: verificationRecord.createdAt
      },
      token
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Server error during registration."
    });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please enter both email and password."
      });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    user.lastLogin = new Date();
    await user.save();

    const verifiedUser = await User.findById(user._id).select("-password").lean();

    const dbAudit = {
      verified: true,
      databaseName: mongoose.connection.name,
      collectionName: User.collection.collectionName,
      documentId: verifiedUser._id.toString(),
      lastLogin: verifiedUser.lastLogin
    };

    const token = generateToken(verifiedUser);

    return res.json({
      success: true,
      message: "Login successful! Account verified in MongoDB.",
      verifiedInDb: true,
      dbAudit,
      user: {
        id: verifiedUser._id,
        name: verifiedUser.name,
        email: verifiedUser.email,
        role: verifiedUser.role,
        lastLogin: verifiedUser.lastLogin
      },
      token
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "Server error during login."
    });
  }
});

router.get("/verify-db/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({
        success: false,
        verified: false,
        message: "Invalid MongoDB ObjectId format."
      });
    }

    const userInDb = await User.findById(userId).select("-password").lean();

    if (!userInDb) {
      return res.status(404).json({
        success: false,
        verified: false,
        message: "User was NOT found in MongoDB database."
      });
    }

    return res.json({
      success: true,
      verified: true,
      message: "User successfully verified in MongoDB!",
      databaseDetails: {
        database: mongoose.connection.name,
        collection: User.collection.collectionName,
        connectionHost: mongoose.connection.host,
        connectionPort: mongoose.connection.port,
        connectionState: mongoose.connection.readyState === 1 ? "Connected" : "Not connected",
        documentId: userInDb._id,
        name: userInDb.name,
        email: userInDb.email,
        role: userInDb.role,
        createdAt: userInDb.createdAt,
        updatedAt: userInDb.updatedAt
      }
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Error querying MongoDB: " + error.message
    });
  }
});

router.get("/stats", async (req, res) => {
  try {
    const count = await User.countDocuments();
    return res.json({
      success: true,
      database: mongoose.connection.name,
      totalUsersStored: count,
      status: "MongoDB Connected and Operational"
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: error.message
    });
  }
});

module.exports = router;
