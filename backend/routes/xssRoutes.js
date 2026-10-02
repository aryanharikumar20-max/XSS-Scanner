const express = require("express");

const XssReport = require("../models/XssReport");
const { scanURL } = require("../scanner/xssScanner");

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const { websiteUrl } = req.body;

    if (!websiteUrl) {
      return res.status(400).json({
        message: "Website URL is required"
      });
    }

    let parsedURL;

    try {
      parsedURL = new URL(websiteUrl);
    } catch {
      return res.status(400).json({
        message: "Invalid URL"
      });
    }

    if (!["http:", "https:"].includes(parsedURL.protocol)) {
      return res.status(400).json({
        message: "Only HTTP and HTTPS URLs are supported"
      });
    }

    const result = await scanURL(websiteUrl);

    const report = new XssReport(result);

    await report.save();

    res.status(201).json({
      message: "Scan completed",
      report
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Error while scanning URL",
      error: error.message
    });
  }
});

router.get("/reports", async (req, res) => {
  try {
    const reports = await XssReport.find().sort({
      createdAt: -1
    });

    res.json(reports);
  } catch (error) {
    res.status(500).json({
      message: "Error fetching reports"
    });
  }
});

module.exports = router;