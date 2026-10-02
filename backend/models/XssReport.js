const mongoose = require("mongoose");

const findingSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true
  },
  category: {
    type: String,
    enum: ["Reflected XSS", "DOM-based XSS", "Stored XSS"],
    required: true
  },
  severity: {
    type: String,
    enum: ["Critical", "High", "Medium", "Low", "None"],
    default: "Low"
  },
  evidence: {
    type: String,
    default: ""
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
});

const xssReportSchema = new mongoose.Schema(
  {
    websiteUrl: {
      type: String,
      required: true
    },
    vulnerability: {
      detected: {
        type: Boolean,
        required: true
      },
      type: {
        type: String,
        default: "No XSS detected"
      },
      severity: {
        type: String,
        default: "None"
      }
    },
    findings: {
      type: [findingSchema],
      default: []
    },
    domAudit: {
      type: Array,
      default: []
    },
    storedAudit: {
      type: Array,
      default: []
    },
    cause: {
      type: String,
      default: ""
    },
    measures: {
      type: [String],
      default: []
    },
    prevention: {
      type: [String],
      default: []
    },
    evidence: {
      parameter: {
        type: String,
        default: ""
      },
      context: {
        type: String,
        default: ""
      }
    },
    status: {
      type: String,
      default: ""
    },
    headerAudit: {
      type: Array,
      default: []
    },
    scannedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

module.exports = mongoose.model("XssReport", xssReportSchema);