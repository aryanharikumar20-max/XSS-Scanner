const axios = require("axios");
const cheerio = require("cheerio");
const https = require("https");

const httpClient = axios.create({
  timeout: 12000,
  headers: {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  },
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  validateStatus: () => true
});

// 1. Analyze HTTP Security Headers
function analyzeHeaders(headers) {
  const findings = [];
  const csp = headers["content-security-policy"];
  const xContentType = headers["x-content-type-options"];
  const xXssProtection = headers["x-xss-protection"];

  if (!csp) {
    findings.push({
      header: "Content-Security-Policy",
      status: "Missing",
      recommendation: "Implement a strict Content Security Policy (CSP) with script-src 'self' or nonce-based restrictions."
    });
  } else {
    findings.push({
      header: "Content-Security-Policy",
      status: "Present",
      value: csp
    });
  }

  if (!xContentType) {
    findings.push({
      header: "X-Content-Type-Options",
      status: "Missing",
      recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME-sniffing."
    });
  }

  return {
    cspPresent: Boolean(csp),
    details: findings
  };
}

// 2. Safe check for unescaped boundary characters
function checkEncodingIntegrity(html, marker) {
  const rawMarker = `${marker}<>"'`;
  const isRawReflected = html.includes(rawMarker);

  const isEncoded =
    html.includes(`${marker}&lt;&gt;&quot;&#39;`) ||
    html.includes(`${marker}&lt;&gt;&quot;&apos;`) ||
    (!isRawReflected && html.includes(marker));

  return {
    isRawReflected,
    isEncoded
  };
}

// 3. DOM-based XSS Static Sink & Source Analyzer
function analyzeDOMSinks(html) {
  const $ = cheerio.load(html);
  const domFindings = [];

  // Patterns for DOM Sources (untrusted client inputs)
  const sourcePatterns = [
    { name: "location.hash", regex: /location\.hash/i },
    { name: "location.search", regex: /location\.search/i },
    { name: "location.href", regex: /location\.href/i },
    { name: "document.URL", regex: /document\.URL/i },
    { name: "document.referrer", regex: /document\.referrer/i },
    { name: "window.name", regex: /window\.name/i },
    { name: "URLSearchParams", regex: /new\s+URLSearchParams/i }
  ];

  // Patterns for DOM Sinks (dangerous execution/rendering sinks)
  const sinkPatterns = [
    { name: "innerHTML", regex: /\.innerHTML\s*=/i },
    { name: "outerHTML", regex: /\.outerHTML\s*=/i },
    { name: "document.write", regex: /document\.write(?:ln)?\s*\(/i },
    { name: "insertAdjacentHTML", regex: /\.insertAdjacentHTML\s*\(/i },
    { name: "eval", regex: /\beval\s*\(/i },
    { name: "setTimeout (string sink)", regex: /setTimeout\s*\(\s*['"`]/i },
    { name: "setInterval (string sink)", regex: /setInterval\s*\(\s*['"`]/i }
  ];

  // Analyze inline script elements
  $("script").each((index, element) => {
    const scriptContent = $(element).html();
    if (!scriptContent) return;

    const lines = scriptContent.split("\n");

    lines.forEach((line, lineNum) => {
      const matchedSources = sourcePatterns.filter((src) => src.regex.test(line));
      const matchedSinks = sinkPatterns.filter((snk) => snk.regex.test(line));

      // Direct source-to-sink on the same line or context
      if (matchedSinks.length > 0) {
        const sinkName = matchedSinks[0].name;
        const blockSources = sourcePatterns.filter((src) => src.regex.test(scriptContent));

        if (blockSources.length > 0 || matchedSources.length > 0) {
          const sourceName = (matchedSources[0] || blockSources[0]).name;
          domFindings.push({
            type: "DOM-based XSS (Unsafe Sink with Client Source)",
            category: "DOM-based XSS",
            severity: "High",
            sink: sinkName,
            source: sourceName,
            snippet: line.trim().substring(0, 120),
            lineNumber: lineNum + 1,
            description: `Client-side script reads from untrusted source '${sourceName}' and writes directly to dangerous sink '${sinkName}'.`
          });
        }
      }
    });
  });

  // Analyze dangerous inline event handlers in DOM elements
  $("*").each((_, element) => {
    const attribs = element.attribs || {};
    for (const [attr, val] of Object.entries(attribs)) {
      if (attr.startsWith("on") && typeof val === "string") {
        const matchedSources = sourcePatterns.filter((src) => src.regex.test(val));
        const matchedSinks = sinkPatterns.filter((snk) => snk.regex.test(val));
        if (matchedSinks.length > 0 && matchedSources.length > 0) {
          domFindings.push({
            type: "DOM-based XSS (Inline Event Handler Sink)",
            category: "DOM-based XSS",
            severity: "High",
            sink: matchedSinks[0].name,
            source: matchedSources[0].name,
            snippet: `${attr}="${val.substring(0, 80)}"`,
            description: `Inline event handler '${attr}' passes user-controlled source to sink '${matchedSinks[0].name}'.`
          });
        }
      }
    }
  });

  return domFindings;
}

// 4. Stored XSS Engine: Probes forms & verifies persistent unescaped reflection
async function analyzeStoredXSS(targetURL, initialHtml) {
  const $ = cheerio.load(initialHtml);
  const forms = $("form");
  const storedFindings = [];

  if (forms.length === 0) {
    return storedFindings;
  }

  for (let i = 0; i < forms.length; i++) {
    const form = $(forms[i]);
    const method = (form.attr("method") || "GET").toUpperCase();
    const actionAttr = form.attr("action") || "";
    const actionURL = new URL(actionAttr, targetURL).toString();

    // Find input fields and textareas
    const inputFields = [];
    form.find("input[type='text'], input[type='search'], input:not([type]), textarea").each((_, input) => {
      const name = $(input).attr("name");
      if (name) inputFields.push(name);
    });

    if (inputFields.length === 0) continue;

    const marker = `audit_stored_${Math.random().toString(36).substring(2, 7)}`;
    const testPayload = `${marker}<>"'`;
    const formData = {};

    inputFields.forEach((name) => {
      formData[name] = testPayload;
    });

    try {
      // Submit the form
      if (method === "POST") {
        await httpClient.post(actionURL, formData, {
          headers: { "Content-Type": "application/x-www-form-urlencoded" }
        });
      } else {
        const getUrl = new URL(actionURL);
        inputFields.forEach((name) => getUrl.searchParams.set(name, testPayload));
        await httpClient.get(getUrl.toString());
      }

      // Re-fetch the target page to verify if probe was stored and returned unescaped
      const verifyRes = await httpClient.get(targetURL);

      const verifyHtml = String(verifyRes.data);
      const { isRawReflected } = checkEncodingIntegrity(verifyHtml, marker);

      if (isRawReflected) {
        storedFindings.push({
          type: "Stored Cross-Site Scripting (Persistent Injection)",
          category: "Stored XSS",
          severity: "Critical",
          targetForm: actionURL,
          method: method,
          testedFields: inputFields,
          description: `User input submitted through form field(s) [${inputFields.join(", ")}] was stored and rendered persistently without HTML entity sanitization.`
        });
      }
    } catch {
      // Continue if submission fails
    }
  }

  return storedFindings;
}

// 5. Main Unified Scanner Function
async function scanURL(targetURL) {
  const url = new URL(targetURL);
  const parameters = [...url.searchParams.keys()];

  try {
    // Initial fetch
    const initialRes = await httpClient.get(targetURL);

    const initialHtml = String(initialRes.data);
    const headerAudit = analyzeHeaders(initialRes.headers);

    const findings = [];
    let reflectedEvidence = { parameter: "", context: "" };
    let primaryCause = "";

    // --- A. REFLECTED XSS SCAN ---
    if (parameters.length > 0) {
      for (const param of parameters) {
        const marker = `audit_ref_${Math.random().toString(36).substring(2, 7)}`;
        const testURL = new URL(targetURL);
        testURL.searchParams.set(param, `${marker}<>"'`);

        const probeRes = await httpClient.get(testURL.toString());

        const responseHtml = String(probeRes.data);
        const { isRawReflected } = checkEncodingIntegrity(responseHtml, marker);

        if (isRawReflected) {
          const $ = cheerio.load(responseHtml);
          let context = "HTML Body Context";
          if ($(`script:contains("${marker}")`).length > 0) {
            context = "Script Tag Context (High Risk)";
          } else if (responseHtml.includes(`="${marker}`)) {
            context = "HTML Attribute Context";
          }

          reflectedEvidence = { parameter: param, context };
          findings.push({
            type: "Reflected Cross-Site Scripting (Unescaped Reflection)",
            category: "Reflected XSS",
            severity: headerAudit.cspPresent ? "Medium" : "High",
            evidence: `Parameter '${param}' reflected unescaped in ${context}`,
            details: { parameter: param, context }
          });
          break;
        }
      }
    }

    // --- B. DOM-BASED XSS SCAN ---
    const domAudit = analyzeDOMSinks(initialHtml);
    domAudit.forEach((domFinding) => {
      findings.push({
        type: domFinding.type,
        category: "DOM-based XSS",
        severity: headerAudit.cspPresent ? "Medium" : domFinding.severity,
        evidence: `${domFinding.sink} reads from ${domFinding.source} (Snippet: "${domFinding.snippet}")`,
        details: domFinding
      });
    });

    // --- C. STORED XSS SCAN ---
    const storedAudit = await analyzeStoredXSS(targetURL, initialHtml);
    storedAudit.forEach((storedFinding) => {
      findings.push({
        type: storedFinding.type,
        category: "Stored XSS",
        severity: storedFinding.severity,
        evidence: `Persistent reflection on form action: ${storedFinding.targetForm} (fields: ${storedFinding.testedFields.join(", ")})`,
        details: storedFinding
      });
    });

    const vulnerabilityDetected = findings.length > 0;

    // Determine highest severity
    let maxSeverity = "None";
    if (findings.some((f) => f.severity === "Critical")) {
      maxSeverity = "Critical";
    } else if (findings.some((f) => f.severity === "High")) {
      maxSeverity = "High";
    } else if (findings.some((f) => f.severity === "Medium")) {
      maxSeverity = "Medium";
    } else if (findings.some((f) => f.severity === "Low")) {
      maxSeverity = "Low";
    }

    // Determine consolidated types
    const uniqueCategories = [...new Set(findings.map((f) => f.category))];
    const consolidatedType = uniqueCategories.length > 0
      ? uniqueCategories.join(" & ")
      : "No XSS Detected";

    // Build measures & prevention
    const measures = [];
    const prevention = [];

    if (vulnerabilityDetected) {
      if (uniqueCategories.includes("Reflected XSS")) {
        measures.push("Apply context-aware HTML entity encoding on all reflected URL parameters.");
        prevention.push("Use context-appropriate output encoding libraries and avoid raw string interpolation.");
      }
      if (uniqueCategories.includes("DOM-based XSS")) {
        measures.push("Replace dangerous DOM sinks like .innerHTML and document.write() with safe APIs (.textContent, .innerText).");
        prevention.push("Sanitize client-side inputs using DOMPurify before inserting dynamic content into the DOM.");
      }
      if (uniqueCategories.includes("Stored XSS")) {
        measures.push("Sanitize and encode persistent database records before rendering them in server-side templates.");
        prevention.push("Adopt strict input validation routines and context-aware templating engines that auto-escape variables.");
      }
      measures.push("Configure a robust Content-Security-Policy (CSP) to restrict script execution contexts.");
      prevention.push("Enforce 'Content-Security-Policy: default-src 'self'' and set 'HttpOnly; SameSite=Strict' flags on authentication cookies.");

      primaryCause = findings.map((f) => f.evidence || f.type).join(" | ");
    } else {
      measures.push("Maintain routine automated input sanitation and regular vulnerability audits.");
      measures.push("Ensure modern HTTP security headers (CSP, X-Content-Type-Options) are present.");
      prevention.push("Continue utilizing context-aware output encoding.");
      prevention.push("Keep client-side frameworks and libraries up to date.");
      primaryCause = "All tested parameters, client-side scripts, and form endpoints safely encode or restrict untrusted input.";
    }

    return {
      websiteUrl: targetURL,
      status: vulnerabilityDetected ? "Vulnerability Detected" : "Safe",
      vulnerability: {
        detected: vulnerabilityDetected,
        type: consolidatedType,
        severity: maxSeverity
      },
      findings: findings,
      domAudit: domAudit,
      storedAudit: storedAudit,
      evidence: reflectedEvidence,
      cause: primaryCause,
      headerAudit: headerAudit.details,
      measures: measures,
      prevention: prevention
    };
  } catch (err) {
    let friendlyMessage = err.message;
    if (err.code === "ECONNABORTED" || err.message.includes("timeout")) {
      friendlyMessage = "Target website timed out or did not respond within 12 seconds.";
    } else if (err.code === "ENOTFOUND") {
      friendlyMessage = "Domain not found (DNS lookup failed). Verify that the URL and domain name are valid.";
    } else if (err.code === "ECONNREFUSED") {
      friendlyMessage = "Connection refused by the target server.";
    }
    throw new Error(`Scanning failed: ${friendlyMessage}`);
  }
}

module.exports = { scanURL };
