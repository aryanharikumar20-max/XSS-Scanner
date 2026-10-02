import { useEffect, useState } from "react";
import axios from "axios";
import "./App.css";
import Auth from "./components/Auth";
import { API_BASE_URL } from "./config";

function App() {
  // Page routing: first page is "auth", then "scanner"
  const [currentPage, setCurrentPage] = useState("auth");

  // Scanner state
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [report, setReport] = useState(null);
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Auth & MongoDB state
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem("xss_user");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [dbStatus, setDbStatus] = useState({
    connected: true,
    database: "xssScannerDB",
    totalUsers: 0
  });

  const [showDbModal, setShowDbModal] = useState(false);
  const [dbModalData, setDbModalData] = useState(null);
  const [dbModalLoading, setDbModalLoading] = useState(false);

  // Fetch MongoDB Stats & Status
  const fetchDbStats = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/api/auth/stats`);
      if (res.data.success) {
        setDbStatus({
          connected: true,
          database: res.data.database || "xssScannerDB",
          totalUsers: res.data.totalUsersStored || 0
        });
      }
    } catch {
      // Backend or DB might be starting
    }
  };

  // Fetch previous scan reports
  const fetchReports = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/api/scan/reports`);
      setReports(response.data);
    } catch (err) {
      console.log("Error fetching reports:", err);
    }
  };

  useEffect(() => {
    fetchReports();
    fetchDbStats();
  }, []);

  // Handle Logout -> automatically returns user to the first page (Auth page)
  const handleLogout = () => {
    localStorage.removeItem("xss_token");
    localStorage.removeItem("xss_user");
    setUser(null);
    setCurrentPage("auth");
    fetchDbStats();
  };

  // Handle successful registration or login
  const handleAuthSuccess = (authUser) => {
    setUser(authUser);
    fetchDbStats();
  };

  // Proceed to the URL Scanner view
  const handleProceedToScanner = () => {
    setCurrentPage("scanner");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Continue as guest
  const handleContinueAsGuest = () => {
    if (!user) {
      setUser({
        name: "Guest Analyst",
        email: "guest@scanner.local",
        role: "guest_analyst",
        isGuest: true
      });
    }
    setCurrentPage("scanner");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // Live DB Verification modal query
  const handleOpenDbVerification = async () => {
    setShowDbModal(true);
    setDbModalLoading(true);
    setDbModalData(null);

    const userId = user?.id || user?._id;
    try {
      if (userId && !user?.isGuest) {
        const res = await axios.get(`${API_BASE_URL}/api/auth/verify-db/${userId}`);
        setDbModalData(res.data);
      } else {
        const res = await axios.get(`${API_BASE_URL}/api/auth/stats`);
        setDbModalData({
          success: true,
          verified: true,
          message: "MongoDB database connection active",
          databaseDetails: {
            database: res.data.database,
            totalUsers: res.data.totalUsersStored,
            sessionMode: user?.isGuest ? "Guest Analyst Mode" : "Authenticated",
            status: "Online & Storing Collections"
          }
        });
      }
    } catch (err) {
      setDbModalData({
        success: false,
        message: err.response?.data?.message || "Could not retrieve MongoDB verification."
      });
    } finally {
      setDbModalLoading(false);
    }
  };

  // Scan URL
  const scanWebsite = async (e) => {
    if (e) e.preventDefault();
    setError("");
    setReport(null);

    if (!websiteUrl.trim()) {
      setError("Please enter a website URL.");
      return;
    }

    try {
      new URL(websiteUrl);
    } catch {
      const sampleUrl = `${API_BASE_URL || window.location.origin}/demo/vulnerable?search=test`;
      setError(`Please enter a valid URL (e.g. ${sampleUrl}).`);
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post(`${API_BASE_URL}/api/scan`, {
        websiteUrl: websiteUrl
      });
      setReport(response.data.report);
      fetchReports();
    } catch (err) {
      console.log(err);
      if (err.response) {
        setError(err.response.data.message || "Scan failed.");
      } else {
        setError("Unable to connect to the backend scanner service. Please verify your backend server is online.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLoad = (url) => {
    setWebsiteUrl(url);
    setError("");
  };

  // Clear current result
  const clearResult = () => {
    setReport(null);
    setWebsiteUrl("");
    setError("");
  };

  const getSeverityBadgeClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "badge-critical";
      case "high":
        return "badge-high";
      case "medium":
        return "badge-medium";
      case "low":
        return "badge-low";
      default:
        return "badge-safe";
    }
  };

  return (
    <div className="app">
      {/* Top Navbar */}
      <nav className="navbar">
        <div className="nav-brand">
          <span className="brand-logo">🛡️</span>
          <span className="brand-title">XSS Sentinel</span>
          <span className="db-status-pill" title="MongoDB Connection Status">
            🟢 MongoDB: {dbStatus.database} ({dbStatus.totalUsers} users)
          </span>
        </div>

        {/* Page Switcher Navigation Tabs */}
        <div className="nav-page-tabs">
          <button
            type="button"
            className={`nav-tab-btn ${currentPage === "auth" ? "active" : ""}`}
            onClick={() => setCurrentPage("auth")}
          >
            <span className="tab-step">1</span>
            <span>🔐 Login & Register</span>
          </button>
          <button
            type="button"
            className={`nav-tab-btn ${currentPage === "scanner" ? "active" : ""}`}
            onClick={() => setCurrentPage("scanner")}
          >
            <span className="tab-step">2</span>
            <span>🛡️ URL Scanner</span>
          </button>
        </div>

        {/* User Profile / Auth Actions */}
        <div className="nav-actions">
          {user ? (
            <div className="user-badge-container">
              <div className="user-avatar" title={user.email}>
                {user.name ? user.name.charAt(0).toUpperCase() : "U"}
              </div>
              <div className="user-info">
                <span className="user-name">{user.name}</span>
                <span className="user-role-tag">
                  {user.role === "security_analyst"
                    ? "Security Analyst"
                    : user.isGuest
                    ? "Guest Analyst"
                    : "Verified User"}
                </span>
              </div>
              <button
                type="button"
                className="btn-verify-user"
                onClick={handleOpenDbVerification}
                title="Verify MongoDB Record Persistence"
              >
                🔍 Verify in DB
              </button>
              <button
                type="button"
                className="nav-btn-logout"
                onClick={handleLogout}
                title="Sign out and return to Login"
              >
                Logout
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="nav-btn nav-btn-primary"
              onClick={() => setCurrentPage("auth")}
            >
              🔐 Sign In / Register
            </button>
          )}
        </div>
      </nav>

      {/* ========================================================================= */}
      {/* PAGE 1: LOGIN & REGISTRATION PAGE                                        */}
      {/* ========================================================================= */}
      {currentPage === "auth" && (
        <div className="auth-page-view">
          {/* Hero Header */}
          <header className="header auth-hero">
            <div className="hero-badge">🔐 Step 1 of 2: Access & Identity Verification</div>
            <h1>🛡️ Authentication & Registration Portal</h1>
            <p>
              Sign in or create an analyst profile persisted in MongoDB to unlock the Cross-Site Scripting (XSS) Vulnerability Scanner.
            </p>
          </header>

          <main className="container auth-page-container">
            <Auth
              onAuthSuccess={handleAuthSuccess}
              currentUser={user}
              onProceedToScanner={handleProceedToScanner}
              onContinueAsGuest={handleContinueAsGuest}
              dbStatus={dbStatus}
            />

            {/* Platform Security Features Grid */}
            <div className="features-preview-grid">
              <div className="feature-item-card">
                <div className="feature-icon">⚡</div>
                <h3>Reflected XSS Engine</h3>
                <p>
                  Automated query parameter fuzzing, payload reflection verification, and context escaping analysis.
                </p>
              </div>

              <div className="feature-item-card">
                <div className="feature-icon">🔬</div>
                <h3>DOM Source-to-Sink</h3>
                <p>
                  AST pattern matching for dangerous sinks like <code>innerHTML</code>, <code>document.write</code>, and <code>eval</code>.
                </p>
              </div>

              <div className="feature-item-card">
                <div className="feature-icon">💾</div>
                <h3>Stored Persistence Audit</h3>
                <p>
                  Target form submission simulation to detect persistent unescaped input stored across sessions.
                </p>
              </div>

              <div className="feature-item-card">
                <div className="feature-icon">🗄️</div>
                <h3>MongoDB Verification</h3>
                <p>
                  Bcrypt encrypted credentials with immediate real-time database validation and audit logging.
                </p>
              </div>
            </div>
          </main>
        </div>
      )}

      {/* ========================================================================= */}
      {/* PAGE 2: URL SCANNER PAGE                                                 */}
      {/* ========================================================================= */}
      {currentPage === "scanner" && (
        <div className="scanner-page-view">
          {/* Scanner Header */}
          <header className="header scanner-hero">
            <div className="hero-badge">🛡️ Step 2 of 2: Automated Vulnerability Assessment</div>
            <h1>🛡️ Comprehensive XSS Vulnerability Scanner</h1>
            <p>
              MERN-Based Security Engine: Automated Reflected, DOM-Based & Stored XSS Detection
            </p>
          </header>

          <main className="container">
            {/* Quick Navigation Banner back to Login/Profile */}
            <div className="scanner-top-bar">
              <div className="scanner-user-status">
                <span>Logged in as: <strong>{user?.name || "Analyst"}</strong></span>
                <span className="status-dot"></span>
                <span>Active Target Scanner</span>
              </div>
              <button
                type="button"
                className="btn-back-auth"
                onClick={() => setCurrentPage("auth")}
              >
                ← Back to Login / Account Settings
              </button>
            </div>

            {/* Scanner Card */}
            <section className="scanner-card">
              <h2>Target Website Scanner</h2>
              <p className="info">
                Enter target URL to run automated security audits across Reflected parameters, DOM sinks/sources, and stored form persistence.
              </p>

              <form onSubmit={scanWebsite}>
                <label htmlFor="target-url-input">Target Website URL</label>
                <input
                  id="target-url-input"
                  type="url"
                  placeholder={`${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/vulnerable?search=test`}
                  value={websiteUrl}
                  onChange={(e) => setWebsiteUrl(e.target.value)}
                />

                {/* Quick Demo Loaders */}
                <div className="demo-section">
                  <span className="demo-label">🧪 Quick Test Target Endpoints:</span>
                  <div className="demo-button-grid">
                    <div className="demo-category">
                      <strong>Reflected XSS:</strong>
                      <button
                        type="button"
                        className="demo-btn-danger"
                        onClick={() =>
                          handleQuickLoad(
                            `${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/vulnerable?search=test`
                          )
                        }
                      >
                        ⚠️ Vulnerable Query
                      </button>
                      <button
                        type="button"
                        className="demo-btn-safe"
                        onClick={() =>
                          handleQuickLoad(
                            `${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/secure?search=test`
                          )
                        }
                      >
                        🛡️ Secure Query
                      </button>
                    </div>

                    <div className="demo-category">
                      <strong>DOM-Based XSS:</strong>
                      <button
                        type="button"
                        className="demo-btn-danger"
                        onClick={() =>
                          handleQuickLoad(
                            `${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/dom-vulnerable`
                          )
                        }
                      >
                        ⚠️ Vulnerable DOM Sink
                      </button>
                      <button
                        type="button"
                        className="demo-btn-safe"
                        onClick={() =>
                          handleQuickLoad(
                            `${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/dom-secure`
                          )
                        }
                      >
                        🛡️ Secure DOM
                      </button>
                    </div>

                    <div className="demo-category">
                      <strong>Stored XSS:</strong>
                      <button
                        type="button"
                        className="demo-btn-danger"
                        onClick={() =>
                          handleQuickLoad(
                            `${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/stored-vulnerable`
                          )
                        }
                      >
                        ⚠️ Vulnerable Guestbook
                      </button>
                      <button
                        type="button"
                        className="demo-btn-safe"
                        onClick={() =>
                          handleQuickLoad(
                            `${API_BASE_URL || (typeof window !== "undefined" ? window.location.origin : "http://localhost:5000")}/demo/stored-secure`
                          )
                        }
                      >
                        🛡️ Secure Guestbook
                      </button>
                    </div>
                  </div>
                </div>

                <div className="button-group">
                  <button
                    type="submit"
                    disabled={loading}
                    className="scan-button"
                  >
                    {loading ? "Analyzing Target with Payloads..." : "🔍 Run Security Audit"}
                  </button>
                  <button
                    type="button"
                    className="clear-button"
                    onClick={clearResult}
                  >
                    Clear
                  </button>
                </div>
              </form>

              {/* Error */}
              {error && <div className="error">⚠️ {error}</div>}
            </section>

            {/* Scan Result */}
            {report && (
              <section className="result-card">
                <div className="result-header">
                  <h2>Vulnerability Audit Report</h2>
                  <span
                    className={
                      report.vulnerability.detected ? "danger-badge" : "safe-badge"
                    }
                  >
                    {report.vulnerability.detected
                      ? "⚠️ Vulnerability Found"
                      : "✅ Target Safe"}
                  </span>
                </div>

                {/* Target URL */}
                <div className="result-item">
                  <h3>🌐 Target URL</h3>
                  <p className="url">{report.websiteUrl}</p>
                </div>

                {/* Overview Grid */}
                <div className="result-grid">
                  <div className="result-box">
                    <h3>Overall Status</h3>
                    <p>{report.status}</p>
                  </div>
                  <div className="result-box">
                    <h3>Detected Types</h3>
                    <p>{report.vulnerability.type}</p>
                  </div>
                  <div className="result-box">
                    <h3>Max Severity</h3>
                    <p
                      className={`severity-tag ${getSeverityBadgeClass(
                        report.vulnerability.severity
                      )}`}
                    >
                      {report.vulnerability.severity}
                    </p>
                  </div>
                  <div className="result-box">
                    <h3>Total Findings</h3>
                    <p>
                      {report.findings?.length ||
                        (report.vulnerability.detected ? 1 : 0)}
                    </p>
                  </div>
                </div>

                {/* Detailed Findings Breakdown */}
                {report.findings && report.findings.length > 0 && (
                  <div className="result-item">
                    <h3>🚨 Detailed Findings ({report.findings.length})</h3>
                    <div className="findings-list">
                      {report.findings.map((finding, idx) => (
                        <div key={idx} className="finding-card">
                          <div className="finding-header">
                            <span className="finding-category">
                              {finding.category}
                            </span>
                            <span
                              className={`finding-severity ${getSeverityBadgeClass(
                                finding.severity
                              )}`}
                            >
                              {finding.severity}
                            </span>
                          </div>
                          <h4 style={{ margin: "6px 0", color: "#111827" }}>
                            {finding.type}
                          </h4>
                          <p style={{ margin: "4px 0", color: "#4b5563" }}>
                            <strong>Evidence:</strong> <code>{finding.evidence}</code>
                          </p>
                          {finding.details?.description && (
                            <p
                              style={{
                                margin: "4px 0",
                                fontSize: "14px",
                                color: "#6b7280"
                              }}
                            >
                              {finding.details.description}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* DOM-Based XSS Audit Details */}
                {report.domAudit && report.domAudit.length > 0 && (
                  <div className="result-item">
                    <h3>🔬 DOM XSS Source-to-Sink Analysis</h3>
                    <table className="dom-table">
                      <thead>
                        <tr>
                          <th>Source (Input)</th>
                          <th>Dangerous Sink</th>
                          <th>Offending Code Snippet</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.domAudit.map((item, idx) => (
                          <tr key={idx}>
                            <td>
                              <span className="code-badge source-badge">
                                {item.source}
                              </span>
                            </td>
                            <td>
                              <span className="code-badge sink-badge">
                                {item.sink}
                              </span>
                            </td>
                            <td>
                              <code>{item.snippet}</code>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Stored XSS Audit Details */}
                {report.storedAudit && report.storedAudit.length > 0 && (
                  <div className="result-item">
                    <h3>💾 Stored XSS Persistence Analysis</h3>
                    <table className="dom-table">
                      <thead>
                        <tr>
                          <th>Target Form Action</th>
                          <th>Method</th>
                          <th>Tested Input Fields</th>
                          <th>Persistence Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.storedAudit.map((item, idx) => (
                          <tr key={idx}>
                            <td>
                              <code>{item.targetForm}</code>
                            </td>
                            <td>
                              <strong>{item.method}</strong>
                            </td>
                            <td>{item.testedFields.join(", ")}</td>
                            <td>
                              <span className="small-danger">
                                Unescaped Storage Confirmed
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Cause Summary */}
                <div className="result-item">
                  <h3>⚠️ Summary Cause</h3>
                  <p>{report.cause}</p>
                </div>

                {/* Security Headers Audit */}
                {report.headerAudit && report.headerAudit.length > 0 && (
                  <div className="result-item">
                    <h3>📋 Security Headers Audit</h3>
                    <ul>
                      {report.headerAudit.map((headerItem, index) => (
                        <li key={index}>
                          <strong>{headerItem.header}:</strong>{" "}
                          <span
                            className={
                              headerItem.status === "Present"
                                ? "header-present"
                                : "header-missing"
                            }
                          >
                            {headerItem.status}
                          </span>
                          {headerItem.value && (
                            <code
                              style={{
                                display: "block",
                                marginTop: "4px",
                                background: "#eee",
                                padding: "4px 8px",
                                borderRadius: "4px"
                              }}
                            >
                              {headerItem.value}
                            </code>
                          )}
                          {headerItem.recommendation && (
                            <p
                              style={{
                                margin: "4px 0 0 0",
                                color: "#666",
                                fontSize: "14px"
                              }}
                            >
                              💡 {headerItem.recommendation}
                            </p>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Measures & Prevention */}
                <div className="result-item">
                  <h3>🔧 Remediation Measures</h3>
                  <ul>
                    {report.measures?.map((measure, index) => (
                      <li key={index}>{measure}</li>
                    ))}
                  </ul>
                </div>

                <div className="result-item">
                  <h3>🛡️ Best Practice Prevention</h3>
                  <ul>
                    {report.prevention?.map((item, index) => (
                      <li key={index}>{item}</li>
                    ))}
                  </ul>
                </div>

                <div className="scan-date">
                  Scanned on: {new Date(report.scannedAt).toLocaleString()}
                </div>
              </section>
            )}

            {/* Scan History Card */}
            <section className="history-card">
              <h2>Recent Scan History</h2>
              {reports.length === 0 ? (
                <p className="no-data">No previous scans recorded.</p>
              ) : (
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Target URL</th>
                        <th>Result</th>
                        <th>XSS Category</th>
                        <th>Severity</th>
                        <th>Timestamp</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reports.slice(0, 10).map((item) => (
                        <tr key={item._id}>
                          <td className="table-url">{item.websiteUrl}</td>
                          <td>
                            <span
                              className={
                                item.vulnerability?.detected
                                  ? "small-danger"
                                  : "small-safe"
                              }
                            >
                              {item.vulnerability?.detected ? "Vulnerable" : "Safe"}
                            </span>
                          </td>
                          <td>{item.vulnerability?.type || "N/A"}</td>
                          <td>
                            <span
                              className={`small-badge ${getSeverityBadgeClass(
                                item.vulnerability?.severity
                              )}`}
                            >
                              {item.vulnerability?.severity || "None"}
                            </span>
                          </td>
                          <td>
                            {new Date(
                              item.scannedAt || item.createdAt
                            ).toLocaleDateString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </main>
        </div>
      )}

      {/* ========================================================================= */}
      {/* LIVE MONGODB VERIFICATION MODAL                                           */}
      {/* ========================================================================= */}
      {showDbModal && (
        <div className="modal-backdrop" onClick={() => setShowDbModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>🔍 MongoDB Persistence Verification</h3>
              <button
                type="button"
                className="modal-close-btn"
                onClick={() => setShowDbModal(false)}
              >
                ✕
              </button>
            </div>
            <div className="modal-body">
              {dbModalLoading ? (
                <p>Querying local MongoDB instance...</p>
              ) : dbModalData ? (
                <div>
                  <div className="db-badge-row">
                    <span className="db-badge-verified">
                      {dbModalData.verified ? "✅ Verified in MongoDB" : "⚠️ Query Result"}
                    </span>
                    <span className="db-badge-connected">
                      Database: {dbStatus.database}
                    </span>
                  </div>
                  <p style={{ marginTop: "10px", color: "#166534" }}>
                    {dbModalData.message}
                  </p>
                  {dbModalData.databaseDetails && (
                    <div className="live-db-response" style={{ marginTop: "12px" }}>
                      <pre>{JSON.stringify(dbModalData.databaseDetails, null, 2)}</pre>
                    </div>
                  )}
                </div>
              ) : (
                <p>No verification data available.</p>
              )}
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn-proceed-app"
                onClick={() => setShowDbModal(false)}
              >
                Close Verification
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Global Footer */}
      <footer>
        <p>XSS Sentinel Security Suite | MERN Application with MongoDB Persistence</p>
      </footer>
    </div>
  );
}

export default App;
