package rustrules

type RustRule struct {
	ID             string
	Type           string
	Value          string
	Message        string // Description of the vulnerability and OWASP category
	Severity       string // Severity level (Low, Medium, High, Critical)
	Recommendation string // How to fix or improve the code
	CWE            string
	IsSafe         bool // CWE identifier
}

var VulnerableRustNodes = []RustRule{
	ArgsOsUsage,
	UnwrapUsage,
	UnsafeBlockUsage,
	ArgsUsageSafe,
	CurrentExeUsage,
	SecureHashSha256,
	InsecureHashMd2,
	InsecureHashMd4,
	InsecureHashMd5,
	InsecureHashSha1,
	ReqwestSafeUsage,
	ReqwestInvalidCerts,
	ReqwestInvalidHostnames,
	ReqwestSetSensitive,
	RustlsDangerousVerifier,
}
var RustlsDangerousVerifier = RustRule{
	ID:             "rustls-dangerous-verifier",
	Type:           "call_expression",
	Value:          "set_certificate_verifier",
	Message:        `Using 'dangerous().set_certificate_verifier()' disables certificate verification in rustls and can expose users to MITM attacks.`,
	Recommendation: `Avoid using the 'dangerous()' API unless implementing a secure, custom verification strategy. Use default verification or safe extensions.`,
	CWE:            "CWE-295: Improper Certificate Validation",
	Severity:       "Critical",
}

var ReqwestSetSensitive = RustRule{
	ID:             "reqwest-set-sensitive",
	Type:           "call_expression",
	Value:          "headers.insert",
	Message:        `Sensitive headers like 'Authorization' must be explicitly marked with 'set_sensitive(true)' to prevent leaking.`,
	Recommendation: `Before inserting the header, call 'header.set_sensitive(true)' to mark it secure.`,
	CWE:            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
	Severity:       "High",
}

var ReqwestInvalidHostnames = RustRule{
	ID:             "reqwest-accept-invalid-hostnames",
	Type:           "call_expression",
	Value:          "danger_accept_invalid_hostnames",
	Message:        `Disabling hostname verification via 'danger_accept_invalid_hostnames(true)' allows MITM attacks.`,
	Recommendation: `Avoid using 'danger_accept_invalid_hostnames'. Use proper TLS validation.`,
	CWE:            "CWE-295: Improper Certificate Validation",
	Severity:       "Critical",
}

var ReqwestInvalidCerts = RustRule{
	ID:             "reqwest-accept-invalid-certs",
	Type:           "call_expression",
	Value:          "danger_accept_invalid_certs",
	Message:        `Disabling certificate validation via 'danger_accept_invalid_certs(true)' exposes the application to MITM attacks.`,
	Recommendation: `Remove 'danger_accept_invalid_certs' or set it to 'false'. Always validate certificates.`,
	CWE:            "CWE-295",
	Severity:       "Critical",
}

var ReqwestSafeUsage = RustRule{
	ID:             "ok-reqwest",
	Type:           "call_expression",
	Value:          "reqwest::Client::builder",
	Message:        `You are securely using 'reqwest::Client::builder()' without disabling TLS verification.`,
	Recommendation: `No action required.`,
	CWE:            "-",
	Severity:       "None",
	IsSafe:         true,
}

var InsecureHashMd2 = RustRule{
	ID:             "insecure-md2",
	Type:           "call_expression",
	Value:          "Md2::new",
	Message:        `MD2 is a broken cryptographic hash function and should not be used for any security-sensitive operations.`,
	Recommendation: `Use SHA-2 (e.g., Sha256) or SHA-3 family algorithms.`,
	CWE:            "CWE-328: Use of Weak Hash",
	Severity:       "High",
}

var InsecureHashMd4 = RustRule{
	ID:             "insecure-md4",
	Type:           "call_expression",
	Value:          "Md4::new",
	Message:        `MD4 is insecure and has been broken. It should not be used for hashing sensitive data.`,
	Recommendation: `Use SHA-2 (e.g., Sha256) or SHA-3.`,
	CWE:            "CWE-328",
	Severity:       "High",
}

var InsecureHashMd5 = RustRule{
	ID:             "insecure-md5",
	Type:           "call_expression",
	Value:          "Md5::new",
	Message:        `MD5 is considered cryptographically broken and unsuitable for further use.`,
	Recommendation: `Use SHA-2 (e.g., Sha256) instead.`,
	CWE:            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
	Severity:       "High",
}

var InsecureHashSha1 = RustRule{
	ID:             "insecure-sha1",
	Type:           "call_expression",
	Value:          "Sha1::new",
	Message:        `SHA-1 has known collision attacks and should no longer be used.`,
	Recommendation: `Use a stronger hash function like Sha256.`,
	CWE:            "CWE-328",
	Severity:       "Medium",
}

var SecureHashSha256 = RustRule{
	ID:             "ok-sha256",
	Type:           "call_expression",
	Value:          "Sha256::new",
	Message:        `Sha256 is a secure cryptographic hash algorithm (SHA-2 family).`,
	Recommendation: `No changes needed. You're using a secure algorithm.`,
	CWE:            "-",
	Severity:       "None",
	IsSafe:         true,
}

var ArgsOsUsage = RustRule{
	ID:    "args-os-usage",
	Type:  "FunctionCall",
	Value: "env::args_os",
	Message: `The use of 'env::args_os()' may lead to platform-dependent behavior when handling non-UTF-8 encoded arguments. 
This can cause logic bugs or crashes when processing command-line input across different operating systems. 
This falls under OWASP Top 10 A01:2021 - Broken Access Control when input parsing impacts program flow or privilege decisions.`,
	Severity: "Medium",
	Recommendation: `Use 'env::args()' instead, which ensures UTF-8 encoded inputs and avoids encoding issues. 
Also validate and sanitize command-line arguments properly before use.`,
	CWE: "CWE-172: Encoding Error",
}
var UnsafeBlockUsage = RustRule{
	ID:             "unsafe-block",
	Type:           "unsafe_block",
	Value:          "unsafe",
	Message:        `Use of 'unsafe' blocks bypasses Rust's memory safety guarantees, which can lead to undefined behavior.`,
	Recommendation: `Avoid using 'unsafe' unless absolutely required. Use safe abstractions and libraries.`,
	CWE:            "CWE-242",
	Severity:       "High",
}

var UnwrapUsage = RustRule{
	ID:             "unwrap-usage",
	Type:           "CallExpression",
	Value:          "unwrap",
	Message:        `Using 'unwrap()' may cause a panic if called on an Err or None value.`,
	Recommendation: `Use proper error handling like 'match', 'unwrap_or', or 'expect()' with error messages.`,
	CWE:            "CWE-248",
	Severity:       "Medium",
}
var ArgsUsageSafe = RustRule{
	ID:             "args-ok",
	Type:           "call_expression",
	Value:          "env::args",
	Message:        `The use of 'env::args()' is safe and ensures UTF-8 encoded input from CLI.`,
	Recommendation: `No action required. You are using the correct function.`,
	CWE:            "-",
	Severity:       "None",
	IsSafe:         true,
}
var CurrentExeUsage = RustRule{
	ID:             "current-exe",
	Type:           "call_expression",
	Value:          "env::current_exe",
	Message:        `Using 'env::current_exe()' can panic or fail in minimal environments or containers where the path to the executable cannot be determined.`,
	Recommendation: `Always check for errors when using 'current_exe()'. Avoid relying on it for critical logic unless fallback logic is implemented.`,
	CWE:            "CWE-703: Improper Check or Handling of Exceptional Conditions",
	Severity:       "Low",
}
