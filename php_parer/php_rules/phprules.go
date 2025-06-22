package phprules

type ASTNode struct {
	ID       string
	Type     string
	Value    string
	Children []*ASTNode
	Parent   *ASTNode
	Message  string
}

var Sha224Hash = &ASTNode{
	ID:      "sha224-hash",
	Type:    "function_call_expression",
	Value:   "sha224", // partial match to cover all sha224 variants
	Message: "Vulnerability: CWE-327; SHA-224 variants are weak, use SHA-256 or stronger.",
}

var OpenSSLDecrypt = &ASTNode{
	ID:      "openssl-decrypt-validate",
	Type:    "function_call_expression",
	Value:   "openssl_decrypt",
	Message: "Vulnerability: CWE-327; openssl_decrypt result must be validated.",
}
var VulnerablePHPNodes = []*ASTNode{
	EmptyWithBoolean,
	AnotherRule,
	AssertUseAudit,
	Sha224Hash,
	OpenSSLDecrypt,
	EchoedRequest,
	PrintedRequest,
	TaintedCallable,
	TaintedExec,
	TaintedFilename,
	TaintedObjectInstantiation,
	TaintedSQLString,
	TaintedURLHost,
	EvalUse,
	ExecUse,
	McryptUse,
	Md5LooseEquality,
	Md5UsedAsPassword,
	WeakCrypto,
}
var WeakCrypto = &ASTNode{
	ID:      "weak-crypto",
	Type:    "call_expression",                                  // Matches tree-sitter’s PHP grammar for function calls
	Value:   "crypt|md5|md5_file|sha1|sha1_file|str_rot13|hash", // Targets weak crypto functions
	Message: "Vulnerability: CWE-327; Use of weak cryptographic functions can lead to insecure hashing; Severity: High",
}

var Md5UsedAsPassword = &ASTNode{
	ID:      "md5-used-as-password",
	Type:    "call_expression", // Matches tree-sitter’s PHP grammar for setPassword calls
	Value:   "setPassword",     // Targets setPassword method calls
	Message: "Vulnerability: CWE-916; Using MD5 for password hashing is insecure due to collision vulnerabilities; Severity: High",
}
var Md5LooseEquality = &ASTNode{
	ID:      "md5-loose-equality",
	Type:    "binary_expression", // Matches tree-sitter’s PHP grammar for == comparisons
	Value:   "==",                // Targets loose equality operator
	Message: "Vulnerability: CWE-697; Loose equality with md5 or md5_file can lead to type juggling vulnerabilities; Severity: Medium",
}
var McryptUse = &ASTNode{
	ID:      "mcrypt-use",
	Type:    "call_expression",                              // Matches tree-sitter’s PHP grammar for function calls
	Value:   "mcrypt_ecb|mcrypt_create_iv|mdecrypt_generic", // Matches mcrypt functions
	Message: "Vulnerability: CWE-327; Use of deprecated mcrypt functions can lead to insecure cryptography; Severity: High",
}
var FileInclusion = &ASTNode{
	ID:      "file-inclusion",
	Type:    "include_statement",                         // Matches tree-sitter’s PHP grammar for include/require
	Value:   "include|include_once|require|require_once", // Matches these functions
	Message: "Vulnerability: CWE-98; Unsanitized user input in file inclusion can lead to remote file inclusion or path traversal; Severity: Critical",
}
var ExecUse = &ASTNode{
	ID:      "exec-use",
	Type:    "call_expression",                                            // Matches tree-sitter’s PHP grammar for command execution functions
	Value:   "exec|passthru|proc_open|popen|shell_exec|system|pcntl_exec", // Matches any of these functions
	Message: "Vulnerability: CWE-78; Command execution with user input can lead to command injection; Severity: Critical",
}
var EvalUse = &ASTNode{
	ID:      "eval-use",
	Type:    "call_expression", // Matches tree-sitter’s PHP grammar for eval
	Value:   "eval",            // Matches eval function
	Message: "Vulnerability: CWE-95; Dynamic code execution via eval with user input can lead to code injection; Severity: Critical",
}
var TaintedURLHost = &ASTNode{
	ID:      "tainted-url-host",
	Type:    "call_expression", // Targets curl_init calls
	Value:   "curl_init",       // Matches curl_init function
	Message: "Vulnerability: CWE-918; Unsanitized user input in URL host can lead to server-side request forgery (SSRF); Severity: High",
}
var TaintedSQLString = &ASTNode{
	ID:      "tainted-sql-string",
	Type:    "call_expression", // Targets mysql_query calls
	Value:   "mysql_query",     // Matches mysql_query function
	Message: "Vulnerability: CWE-89; Unsanitized user input in SQL query can lead to SQL injection; Severity: Critical",
}
var TaintedObjectInstantiation = &ASTNode{
	ID:      "tainted-object-instantiation",
	Type:    "object_creation_expression", // Matches tree-sitter’s PHP grammar for `new`
	Value:   "",                           // Empty value to match any dynamic class name
	Message: "Vulnerability: CWE-470; Unsanitized user input in dynamic object instantiation can lead to arbitrary code execution; Severity: Critical",
}
var TaintedFilename = &ASTNode{
	ID:      "tainted-filename",
	Type:    "call_expression", // Matches tree-sitter’s type for hash_file/file
	Value:   "hash_file|file",  // Partial match for function names
	Message: "Vulnerability: CWE-73; Unsanitized user input in filename can lead to file access vulnerabilities; Severity: High",
}
var TaintedExec = &ASTNode{
	ID:      "tainted-exec",
	Type:    "call_expression",  // Matches tree-sitter’s type for system/proc_open
	Value:   "system|proc_open", // Partial match for function names
	Message: "Vulnerability: CWE-78; Command injection via unsanitized user input in system/proc_open; Severity: Critical",
}
var TaintedCallable = &ASTNode{
	ID:      "tainted-callable",
	Type:    "function_call",
	Value:   "usort",
	Message: "Vulnerability: CWE-829; User-controlled data used as a callable function.",
}

var PrintedRequest = &ASTNode{
	ID:      "printed-request",
	Type:    "expression_statement",
	Value:   "print",
	Message: "Vulnerability: CWE-79 (XSS); User input is printed without sanitization.",
}

var EchoedRequest = &ASTNode{
	ID:      "echoed-request",
	Type:    "echo_statement",
	Value:   "echo", // Use for partial match
	Message: "Vulnerability: CWE-79; Echoing unsanitized user input can lead to XSS attacks.",
}

var EmptyWithBoolean = &ASTNode{
	ID:      "empty-with-boolean-expression",
	Type:    "if_statement",
	Value:   "empty($params['name'] && !empty($params['pass']))", // partial match is okay
	Message: "Vulnerability: CWE-758; Use empty() on individual values.",
}

var AnotherRule = &ASTNode{
	ID:      "some-id",
	Type:    "call_expression",
	Value:   `eval($_GET['input'])`,
	Message: "Vulnerability: Code injection via eval()",
}
var AssertUseAudit = &ASTNode{
	ID:      "assert-use-audit",
	Type:    "function_call_expression",
	Value:   `assert`, // Match the function name only
	Message: "Vulnerability: CWE-676; Avoid assert() with user input or dynamic expressions.",
}
