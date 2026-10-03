const express = require("express");
const router = express.Router();

// Helper to escape HTML characters (Secure implementation)
function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

let storedVulnerableComments = [
  "Welcome to the demo guestbook!",
  "Feel free to leave a review."
];

let storedSecureComments = [
  "Welcome to the secure guestbook!",
  "All inputs are sanitized before rendering."
];

router.get("/vulnerable", (req, res) => {
  const query = req.query.search || "guest";

  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Vulnerable Search (Reflected XSS)</title>
      <style>body { font-family: sans-serif; padding: 20px; }</style>
    </head>
    <body>
      <h1>Search Results (Reflected XSS Demo)</h1>
      <p>You searched for: ${query}</p>
      <div>No products matched your search.</div>
    </body>
    </html>
  `;

  res.send(htmlResponse);
});

router.get("/secure", (req, res) => {
  const query = req.query.search || "guest";

  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");

  const safeQuery = escapeHtml(query);

  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Secure Search (Reflected Protected)</title>
      <style>body { font-family: sans-serif; padding: 20px; }</style>
    </head>
    <body>
      <h1>Search Results (Secure Demo)</h1>
      <p>You searched for: ${safeQuery}</p>
      <div>No products matched your search.</div>
    </body>
    </html>
  `;

  res.send(htmlResponse);
});

router.get("/dom-vulnerable", (req, res) => {
  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Vulnerable DOM XSS Demo</title>
      <style>body { font-family: sans-serif; padding: 20px; }</style>
    </head>
    <body>
      <h1>User Profile (DOM XSS Demo)</h1>
      <p>Greeting:</p>
      <div id="greeting-output">Loading...</div>

      <script>
        // Vulnerable Pattern: Reading client source (location.search / location.hash)
        // and writing directly into an unsafe DOM sink (.innerHTML)
        const params = new URLSearchParams(window.location.search);
        const name = params.get('name') || window.location.hash.substring(1) || 'Visitor';
        document.getElementById('greeting-output').innerHTML = 'Hello, ' + name + '!';
      </script>
    </body>
    </html>
  `;

  res.send(htmlResponse);
});

router.get("/dom-secure", (req, res) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");

  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Secure DOM Demo</title>
      <style>body { font-family: sans-serif; padding: 20px; }</style>
    </head>
    <body>
      <h1>User Profile (Secure DOM Demo)</h1>
      <p>Greeting:</p>
      <div id="greeting-output">Loading...</div>

      <script>
        // Secure Pattern: Using textContent or innerText instead of innerHTML
        const params = new URLSearchParams(window.location.search);
        const name = params.get('name') || window.location.hash.substring(1) || 'Visitor';
        document.getElementById('greeting-output').textContent = 'Hello, ' + name + '!';
      </script>
    </body>
    </html>
  `;

  res.send(htmlResponse);
});

router.get("/stored-vulnerable", (req, res) => {
  const commentsList = storedVulnerableComments
    .map((c) => `<li>${c}</li>`)
    .join("");

  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Vulnerable Guestbook (Stored XSS)</title>
      <style>body { font-family: sans-serif; padding: 20px; } input, textarea, button { margin: 5px 0; }</style>
    </head>
    <body>
      <h1>Guestbook (Stored XSS Demo)</h1>
      <form method="POST" action="/demo/stored-vulnerable/comment">
        <label for="comment">Leave a comment:</label><br/>
        <input type="text" id="comment" name="comment" placeholder="Write something..." required /><br/>
        <button type="submit">Post Comment</button>
      </form>
      <h2>Existing Comments:</h2>
      <ul>
        ${commentsList}
      </ul>
    </body>
    </html>
  `;

  res.send(htmlResponse);
});

router.post("/stored-vulnerable/comment", (req, res) => {
  const { comment } = req.body;
  if (comment) {
    // Insecurely stored without sanitization or encoding
    storedVulnerableComments.push(comment);
  }
  res.redirect("/demo/stored-vulnerable");
});

// 3B. Secure Stored XSS Page & Submission
router.get("/stored-secure", (req, res) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");

  const commentsList = storedSecureComments
    .map((c) => `<li>${escapeHtml(c)}</li>`)
    .join("");

  const htmlResponse = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Secure Guestbook (Stored Protected)</title>
      <style>body { font-family: sans-serif; padding: 20px; } input, textarea, button { margin: 5px 0; }</style>
    </head>
    <body>
      <h1>Guestbook (Secure Demo)</h1>
      <form method="POST" action="/demo/stored-secure/comment">
        <label for="comment">Leave a comment:</label><br/>
        <input type="text" id="comment" name="comment" placeholder="Write something..." required /><br/>
        <button type="submit">Post Comment</button>
      </form>
      <h2>Existing Comments:</h2>
      <ul>
        ${commentsList}
      </ul>
    </body>
    </html>
  `;

  res.send(htmlResponse);
});

router.post("/stored-secure/comment", (req, res) => {
  const { comment } = req.body;
  if (comment) {
    // Sanitized and escaped
    storedSecureComments.push(escapeHtml(comment));
  }
  res.redirect("/demo/stored-secure");
});

// Helper route to reset stored demo comments
router.get("/stored-reset", (req, res) => {
  storedVulnerableComments = [
    "Welcome to the demo guestbook!",
    "Feel free to leave a review."
  ];
  storedSecureComments = [
    "Welcome to the secure guestbook!",
    "All inputs are sanitized before rendering."
  ];
  res.json({ message: "Stored comments reset to defaults." });
});

module.exports = router;
