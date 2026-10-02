import { useState } from "react";
import axios from "axios";
import { API_BASE_URL } from "../config";

function Auth({
  onAuthSuccess,
  initialMode = "register",
  currentUser,
  onProceedToScanner,
  onContinueAsGuest,
  dbStatus
}) {
  const [mode, setMode] = useState(initialMode); // 'login' or 'register'
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: ""
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [verificationResult, setVerificationResult] = useState(null);
  const [reverifying, setReverifying] = useState(false);
  const [liveCheckData, setLiveCheckData] = useState(null);
  const [showSwitchForm, setShowSwitchForm] = useState(false);

  const handleChange = (e) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
    setError("");
  };

  // Helper to quickly fill demo security credentials for rapid testing/grading
  const handleFillDemo = (targetMode) => {
    setError("");
    if (targetMode === "register") {
      setFormData({
        name: "Security Analyst",
        email: `analyst_${Math.floor(1000 + Math.random() * 9000)}@security.local`,
        password: "Password123!",
        confirmPassword: "Password123!"
      });
    } else {
      setFormData({
        name: "",
        email: "analyst@security.local",
        password: "Password123!",
        confirmPassword: ""
      });
    }
  };

  const handleRegister = async (e) => {
    if (e) e.preventDefault();
    setError("");
    setVerificationResult(null);
    setLiveCheckData(null);

    if (!formData.name.trim()) {
      setError("Please enter your full name.");
      return;
    }
    if (!formData.email.trim()) {
      setError("Please enter your email address.");
      return;
    }
    if (formData.password.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }
    if (formData.password !== formData.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post(`${API_BASE_URL}/api/auth/register`, {
        name: formData.name.trim(),
        email: formData.email.trim(),
        password: formData.password
      });

      const { user, token, dbAudit, message } = response.data;

      // Save credentials to localStorage
      localStorage.setItem("xss_token", token);
      localStorage.setItem("xss_user", JSON.stringify(user));

      // Set explicit MongoDB verification details to display to the user
      setVerificationResult({
        success: true,
        message,
        dbAudit,
        user
      });

      if (onAuthSuccess) {
        onAuthSuccess(user, token, dbAudit);
      }
    } catch (err) {
      console.error("Registration error:", err);
      if (err.response && err.response.data && err.response.data.message) {
        setError(err.response.data.message);
      } else {
        setError("Unable to connect to backend server. Make sure MongoDB and backend are running.");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e) => {
    if (e) e.preventDefault();
    setError("");
    setVerificationResult(null);
    setLiveCheckData(null);

    if (!formData.email.trim() || !formData.password) {
      setError("Please enter both email and password.");
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post(`${API_BASE_URL}/api/auth/login`, {
        email: formData.email.trim(),
        password: formData.password
      });

      const { user, token, dbAudit, message } = response.data;

      localStorage.setItem("xss_token", token);
      localStorage.setItem("xss_user", JSON.stringify(user));

      setVerificationResult({
        success: true,
        message,
        dbAudit,
        user
      });

      if (onAuthSuccess) {
        onAuthSuccess(user, token, dbAudit);
      }

      // Automatically transition to the scanner upon successful login
      if (onProceedToScanner) {
        setTimeout(() => {
          onProceedToScanner();
        }, 350);
      }
    } catch (err) {
      console.error("Login error:", err);
      if (err.response && err.response.data && err.response.data.message) {
        setError(err.response.data.message);
      } else {
        setError("Invalid email or password. Please verify credentials or register a new user.");
      }
    } finally {
      setLoading(false);
    }
  };

  // Perform an on-demand live query directly to MongoDB to prove the user document exists
  const handleLiveDbCheck = async () => {
    const userId =
      verificationResult?.user?.id ||
      verificationResult?.user?._id ||
      currentUser?.id ||
      currentUser?._id;

    if (!userId) return;

    setReverifying(true);
    try {
      const res = await axios.get(`${API_BASE_URL}/api/auth/verify-db/${userId}`);
      setLiveCheckData(res.data);
    } catch (err) {
      console.error("Database check failed:", err);
    } finally {
      setReverifying(false);
    }
  };

  return (
    <div className="auth-card">
      {/* If a session is already detected and the user hasn't explicitly clicked to switch */}
      {currentUser && !showSwitchForm && !verificationResult && (
        <div className="active-session-card">
          <div className="session-status-chip">
            <span className="pulse-dot"></span> Active Analyst Session
          </div>
          <div className="session-user-row">
            <div className="session-avatar">
              {currentUser.name ? currentUser.name.charAt(0).toUpperCase() : "U"}
            </div>
            <div className="session-info">
              <h3>{currentUser.name}</h3>
              <p className="session-email">{currentUser.email}</p>
              <span className="session-badge">
                Role: {currentUser.role === "security_analyst" ? "Security Analyst" : "Verified User"}
              </span>
            </div>
          </div>

          <div className="session-actions">
            <button
              type="button"
              className="btn-proceed-large"
              onClick={onProceedToScanner}
            >
              🚀 Launch URL Scanner Suite →
            </button>
            <button
              type="button"
              className="btn-switch-account"
              onClick={() => setShowSwitchForm(true)}
            >
              🔄 Sign In with Another Account / Register
            </button>
          </div>
        </div>
      )}

      {/* Main Authentication Form & Verification Container */}
      {(!currentUser || showSwitchForm || verificationResult) && (
        <>
          {/* Auth Card Header with Mode Toggle */}
          <div className="auth-header">
            <div className="auth-tabs">
              <button
                type="button"
                className={`auth-tab ${mode === "login" ? "active" : ""}`}
                onClick={() => {
                  setMode("login");
                  setError("");
                  setVerificationResult(null);
                }}
              >
                🔐 Sign In (Login)
              </button>
              <button
                type="button"
                className={`auth-tab ${mode === "register" ? "active" : ""}`}
                onClick={() => {
                  setMode("register");
                  setError("");
                  setVerificationResult(null);
                }}
              >
                👤 Create Account (Register)
              </button>
            </div>

            {/* Quick Demo Autofill Helper */}
            <div className="auth-header-actions">
              <button
                type="button"
                className="btn-demo-autofill"
                onClick={() => handleFillDemo(mode)}
                title="Fill credentials for testing"
              >
                ⚡ Fill Demo Info
              </button>
            </div>
          </div>

          <div className="auth-body">
            {/* Verification Success Box when user registers / logs in */}
            {verificationResult && (
              <div className="db-verification-banner">
                <div className="db-verification-header">
                  <span className="db-badge-verified">✅ Verified in MongoDB</span>
                  <span className="db-badge-connected">
                    Database: {verificationResult.dbAudit?.databaseName || "xssScannerDB"}
                  </span>
                </div>

                <h3>{verificationResult.message}</h3>
                <p className="db-verification-summary">
                  The user document has been validated, indexed, and stored in your local MongoDB instance.
                </p>

                <div className="db-details-grid">
                  <div className="db-detail-item">
                    <span className="db-detail-label">MongoDB Document _id:</span>
                    <code className="db-detail-value">{verificationResult.dbAudit?.documentId}</code>
                  </div>
                  <div className="db-detail-item">
                    <span className="db-detail-label">MongoDB Collection:</span>
                    <code className="db-detail-value">{verificationResult.dbAudit?.collectionName || "users"}</code>
                  </div>
                  <div className="db-detail-item">
                    <span className="db-detail-label">Registered Name:</span>
                    <span className="db-detail-value">{verificationResult.user?.name}</span>
                  </div>
                  <div className="db-detail-item">
                    <span className="db-detail-label">Registered Email:</span>
                    <span className="db-detail-value">{verificationResult.user?.email}</span>
                  </div>
                  <div className="db-detail-item">
                    <span className="db-detail-label">Timestamp:</span>
                    <span className="db-detail-value">
                      {new Date(verificationResult.user?.createdAt || Date.now()).toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Primary Proceed Button */}
                <div className="db-action-row">
                  <button
                    type="button"
                    className="btn-proceed-app"
                    onClick={onProceedToScanner}
                  >
                    🚀 Proceed to URL Scanner Suite →
                  </button>
                  <button
                    type="button"
                    className="btn-recheck-db"
                    onClick={handleLiveDbCheck}
                    disabled={reverifying}
                  >
                    {reverifying ? "Querying MongoDB..." : "🔍 Query Live MongoDB Record Now"}
                  </button>
                </div>

                {/* Live Query Results */}
                {liveCheckData && (
                  <div className="live-db-response">
                    <h4>🟢 Direct MongoDB Query Response (200 OK):</h4>
                    <pre>{JSON.stringify(liveCheckData.databaseDetails, null, 2)}</pre>
                  </div>
                )}
              </div>
            )}

            {/* Auth Form (hidden if just verified) */}
            {!verificationResult && (
              <>
                <div className="auth-form-intro">
                  <h2>{mode === "login" ? "Sign In to Access Scanner" : "Create Security Analyst Account"}</h2>
                  <p className="info">
                    {mode === "login"
                      ? "Authenticate with your MongoDB registered account to unlock the full XSS vulnerability analysis suite."
                      : "Register your profile into MongoDB to store scan logs, analyze vulnerabilities, and inspect live persistence."}
                  </p>
                </div>

                {error && <div className="error">⚠️ {error}</div>}

                <form onSubmit={mode === "register" ? handleRegister : handleLogin} className="auth-form">
                  {mode === "register" && (
                    <div className="form-group">
                      <label htmlFor="auth-name">Full Name</label>
                      <input
                        id="auth-name"
                        name="name"
                        type="text"
                        placeholder="e.g. Aryan Harikumar"
                        value={formData.name}
                        onChange={handleChange}
                        required
                      />
                    </div>
                  )}

                  <div className="form-group">
                    <label htmlFor="auth-email">Email Address</label>
                    <input
                      id="auth-email"
                      name="email"
                      type="email"
                      placeholder="e.g. analyst@security.local"
                      value={formData.email}
                      onChange={handleChange}
                      required
                    />
                  </div>

                  <div className="form-group">
                    <label htmlFor="auth-password">Password</label>
                    <input
                      id="auth-password"
                      name="password"
                      type="password"
                      placeholder="At least 6 characters"
                      value={formData.password}
                      onChange={handleChange}
                      required
                    />
                  </div>

                  {mode === "register" && (
                    <div className="form-group">
                      <label htmlFor="auth-confirm-password">Confirm Password</label>
                      <input
                        id="auth-confirm-password"
                        name="confirmPassword"
                        type="password"
                        placeholder="Re-enter your password"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        required
                      />
                    </div>
                  )}

                  <div className="form-submit-row">
                    <button type="submit" className="scan-button auth-submit-btn" disabled={loading}>
                      {loading
                        ? mode === "register"
                          ? "Registering & Verifying in MongoDB..."
                          : "Validating with MongoDB..."
                        : mode === "register"
                        ? "💾 Register & Store in MongoDB"
                        : "🚀 Sign In & Open URL Scanner"}
                    </button>
                  </div>
                </form>

                {/* Guest access bypass option for rapid testing */}
                <div className="guest-bypass-footer">
                  <span className="guest-text">Need to test immediately?</span>
                  <button
                    type="button"
                    className="guest-link-btn"
                    onClick={onContinueAsGuest}
                  >
                    Continue to URL Scanner as Guest →
                  </button>
                </div>
              </>
            )}
          </div>
        </>
      )}

      {/* Database Status Footer Banner */}
      <div className="auth-footer-bar">
        <span>🛡️ MERN Security Suite</span>
        <span>
          🗄️ MongoDB: <strong>{dbStatus?.database || "xssScannerDB"}</strong> (
          {dbStatus?.totalUsers || 0} registered users)
        </span>
      </div>
    </div>
  );
}

export default Auth;
