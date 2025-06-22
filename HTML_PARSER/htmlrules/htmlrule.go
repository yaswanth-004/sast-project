package htmlrule

type ASTNode struct {
	ID       string
	Type     string
	Value    string
	Children []*ASTNode
	Parent   *ASTNode
	Message  string
}

var VulnerableHTMLNodes = []*ASTNode{
	InlineScriptTag,
	OnErrorAttribute,
	JavascriptHref,
	RobotsDenied,
	BadHttpEquiv,
	EvalDetected,
	InsecureDocumentMethod,
	PlaintextHTTPLink,
}

var InlineScriptTag = &ASTNode{
	ID:      "html-inline-script",
	Type:    "element",
	Value:   "script",
	Message: "Vulnerability: Inline JavaScript execution. CWE-79 (XSS); Severity: High; Recommendation: Move JavaScript to external files and use CSP headers.",
}

var OnErrorAttribute = &ASTNode{
	ID:      "html-onerror-attribute",
	Type:    "attribute",
	Value:   "onerror",
	Message: "Vulnerability: JavaScript execution via 'onerror'. CWE-79 (XSS); Severity: Medium; Recommendation: Sanitize user-controlled image/file attributes.",
}

var JavascriptHref = &ASTNode{
	ID:      "html-javascript-href",
	Type:    "attribute_value",
	Value:   "javascript:",
	Message: "Vulnerability: Dangerous URI scheme in href. CWE-79 (XSS); Severity: Medium; Recommendation: Avoid using 'javascript:' in anchor tags.",
}

var RobotsDenied = &ASTNode{
	ID:      "robots-denied",
	Type:    "attribute_value",
	Value:   "noindex, nofollow",
	Message: "Vulnerability: Disallowing search engine indexing. CWE-200 (Information Exposure); Recommendation: Confirm this is intentional.",
}

var BadHttpEquiv = &ASTNode{
	ID:      "https-equiv",
	Type:    "attribute_name",
	Value:   "https-equiv",
	Message: "Vulnerability: Invalid or malformed 'https-equiv' attribute. CWE-20 (Input Validation); Recommendation: Use standard 'http-equiv' and quote attribute values.",
}

var EvalDetected = &ASTNode{
	ID:      "eval-detected",
	Type:    "call_expression",
	Value:   "eval",
	Message: "Vulnerability: Usage of eval(). CWE-95; Severity: High; Recommendation: Avoid using eval(); use safer alternatives.",
}

var InsecureDocumentMethod = &ASTNode{
	ID:      "insecure-document-method",
	Type:    "member_expression",
	Value:   "innerHTML",
	Message: "Vulnerability: Use of innerHTML can lead to XSS. CWE-79; Severity: High; Recommendation: Use safe DOM manipulation techniques or sanitization.",
}

var PlaintextHTTPLink = &ASTNode{
	ID:      "plaintext-http-link",
	Type:    "attribute_value",
	Value:   "http://semgrep.dev",
	Message: "Vulnerability: Insecure HTTP link. CWE-319; Severity: Medium; Recommendation: Use HTTPS instead of HTTP to avoid man-in-the-middle attacks.",
}
