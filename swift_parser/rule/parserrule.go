package parserrule

// ASTNode represents a vulnerability rule
type ASTNode struct {
	ID       string
	Type     string
	Value    string
	Children []*ASTNode
	Parent   *ASTNode
	Message  string
}

// VulnerableSwiftNodes contains all Swift vulnerability rules
var VulnerableSwiftNodes = []*ASTNode{
	InsecureRandom,
	SwiftUserDefaults,
	SwiftPotentialSQLiteInjection,
	SwiftWebViewConfig,
}

// InsecureRandom detects insecure random number generation
var InsecureRandom = &ASTNode{
	ID:      "insecure-random",
	Type:    "call_expression",
	Value:   ".random", // Broadened to catch Int.random, Double.random, etc.
	Message: "Vulnerability: CWE-330 (Use of Insufficiently Random Values); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: Medium; Recommendation: Use a cryptographically secure random number generator like SecRandomCopyBytes() for security-sensitive operations.",
}

// SwiftUserDefaults detects insecure storage in UserDefaults
var SwiftUserDefaults = &ASTNode{
	ID:      "swift-user-defaults",
	Type:    "call_expression",
	Value:   "UserDefaults.standard.set",
	Message: "Vulnerability: CWE-312 (Cleartext Storage of Sensitive Information); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Avoid storing sensitive data (e.g., passwords, API keys) in UserDefaults. Use Keychain for secure storage.",
}

// SwiftPotentialSQLiteInjection detects potential SQL injection in SQLite queries
var SwiftPotentialSQLiteInjection = &ASTNode{
	ID:      "swift-potential-sqlite-injection",
	Type:    "string_literal",
	Value:   "SELECT", // Broadened to catch any SELECT query
	Message: "Vulnerability: CWE-89 (SQL Injection); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use parameterized queries with sqlite3_prepare_v2 and sqlite3_bind_* to prevent SQL injection.",
}

// SwiftWebViewConfig detects insecure WKWebView configuration
var SwiftWebViewConfig = &ASTNode{
	ID:      "swift-webview-config-allows-js-open-windows",
	Type:    "assignment_expression",
	Value:   "JavaScriptCanOpenWindowsAutomatically",
	Message: "Vulnerability: CWE-79 (Cross-Site Scripting); OWASP Top 10: A03:2021 - Injection; Severity: Medium; Recommendation: Set JavaScriptCanOpenWindowsAutomatically to false to prevent unauthorized window openings in WKWebView.",
}
