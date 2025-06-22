package baseh_operation

type ASTNode struct {
	ID       string
	Type     string
	Value    string
	Children []*ASTNode
	Parent   *ASTNode
	Message  string // Added field to store vulnerability details
}

var VulnerableBashNodes = []*ASTNode{
	EchoPlusMessage,
	SleepFormatHowlong,
	UnsafeTemplateMsg,
	EchoFStringMessage,
	AttrEmptyDict,
	AttrEmptyList,
	AttrSomeDict,
	AttrSomeList,
	AttrSomeSet,
	AttrMySet,
	CreateSubprocessFromEventArgs,
	CreateSubprocessFromEventCmd,
	SubprocessExecWithArgs,
	SubprocessExecWithCmd,
	LoopSubprocessShellEventCmd,
	AsyncioCreateShellEventCmd,
	SpawnlpEventCmd,
	SpawnlpeEventCmd,
	SpawnvFString,
	SpawnveEventCmd,
	SpawnveWithShell,
	SpawnlFString,
	SpawnlEventCmd,
	CallFormatShell,
	CallCmdListShell,
	CallFormatShellCwd,
	PopenWithShell,
	PopenShellText,
	OsSystemFStringDir,
	DynamoDBQueryWithFilter,
	DynamoDBScanWithFilter,
	MySQLSqliUpdatePublicIP,
	Psycopg2SQLiQuery,
	PymssqlSQLiQuery,
	PyMySQLSqliQuery,
	SQLAlchemySqliQuery,
	ExecTaintedFormat,
	TaintedHTMLResponse,
	PickleLoadExploitCode,
	CPickleLoadsFString,
	DillLoadsCall,
	ShelveOpenFString,
	TaintedSQLStringFormat,
	BokehImportWidgetBox,
	BokehImportFromNetworkx,
	BokehWidgetBoxCall,
	BokehFromNetworkxCall,
	Boto3ClientHardcodedSecret,
	Boto3SessionHardcodedSecret,
	Boto3SessionsSessionHardcodedKey,
	Boto3ResourceHardcodedKeySecret,
	Boto3ResourceHardcodedSecret,
	ClickEchoWithStyle,
	ClickEchoWithStyleColor,
	RecordAndZeroCheck,
	AttrAndZeroCheck,
	DictAttrAndZeroCheck,
	ShutdownFollowedByClose,
	ShutdownFollowedByClose2,
	ShutdownFollowedByClose3,
	EmptyAESKey,
	InsecureCipherAlgorithmARC4,
	InsecureCipherModeNone,
	InsecureCipherAlgorithmBlowfish,
	InsecureCipherAlgorithmIDEA,
	InsecureCipherModeECB,
	InsecureHashAlgorithmMD5,
}

// Insecure Hash Algorithm MD5
var InsecureHashAlgorithmMD5 = &ASTNode{
	ID:      "insecure_hash_algorithm_md5",
	Type:    "call",
	Value:   "hashes.MD5()",
	Message: "Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Use secure hash algorithms like SHA-256 or SHA-3 instead of MD5, which is cryptographically broken and susceptible to collision attacks.",
}

// Insecure Cipher Mode ECB
var InsecureCipherModeECB = &ASTNode{
	ID:      "insecure_cipher_mode_ecb",
	Type:    "call",
	Value:   "ECB(",
	Message: "Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Avoid ECB mode as it does not provide semantic security. Use secure modes like GCM or CBC with a proper initialization vector (IV).",
}

// Insecure Cipher Algorithm IDEA
var InsecureCipherAlgorithmIDEA = &ASTNode{
	ID:      "insecure_cipher_algorithm_idea",
	Type:    "call",
	Value:   `Cipher(algorithms.IDEA(key), mode=None, backend=default_backend())`,
	Message: "Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Replace IDEA with stronger algorithms like AES, which is widely regarded as secure and efficient.",
}

// Insecure Cipher Algorithm Blowfish
var InsecureCipherAlgorithmBlowfish = &ASTNode{
	ID:      "insecure_cipher_algorithm_blowfish",
	Type:    "call",
	Value:   `Cipher(algorithms.Blowfish(key), mode=None, backend=default_backend())`,
	Message: "Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Use AES instead of Blowfish, as Blowfish has known vulnerabilities and smaller key sizes that reduce its security.",
}

// Insecure Cipher Mode None
var InsecureCipherModeNone = &ASTNode{
	ID:      "insecure_cipher_mode_none",
	Type:    "call",
	Value:   `Cipher(algorithms.AES(key), mode=None, backend=default_backend())`,
	Message: "Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Always specify a secure cipher mode (e.g., GCM or CBC) with a proper IV to ensure confidentiality and integrity.",
}

// Insecure Cipher Algorithm ARC4
var InsecureCipherAlgorithmARC4 = &ASTNode{
	ID:      "insecure_cipher_algorithm_arc4",
	Type:    "call",
	Value:   `Cipher(algorithms.AES(key), mode=None, backend=default_backend())`,
	Message: "Vulnerability: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Avoid ARC4 due to its cryptographic weaknesses. Use AES with a secure mode like GCM for encryption.",
}

// Empty AES Key
var EmptyAESKey = &ASTNode{
	ID:      "empty_aes_key",
	Type:    "call",
	Value:   `AES.new("", AES.MODE_CFB, iv)`,
	Message: "Vulnerability: CWE-321 (Use of Hard-coded Cryptographic Key); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: Critical; Recommendation: Never use empty or hard-coded keys. Use secure key management practices, such as generating keys dynamically and storing them securely (e.g., in a key vault).",
}

// Echo + Message
var EchoPlusMessage = &ASTNode{
	ID:    "node_echo_plus",
	Type:  "binary_expression",
	Value: `"echo " + message`,
	Children: []*ASTNode{
		{
			ID:    "node_echo_str",
			Type:  "string",
			Value: `"echo "`,
		},
		{
			ID:    "node_msg_ident",
			Type:  "identifier",
			Value: "message",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid constructing OS commands with user input. Use parameterized commands or subprocess with lists to prevent command injection.",
}

// Sleep Format Howlong
var SleepFormatHowlong = &ASTNode{
	ID:    "node_sleep_fmt",
	Type:  "call",
	Value: `"sleep {}".format(howlong)`,
	Children: []*ASTNode{
		{
			ID:    "node_format_str",
			Type:  "string",
			Value: `"sleep {}"`,
		},
		{
			ID:    "node_arg_ident",
			Type:  "identifier",
			Value: "howlong",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize user input or use subprocess with a list of arguments to avoid command injection risks.",
}

// Unsafe Templated String
var UnsafeTemplateMsg = &ASTNode{
	ID:    "node_unsafe_tmpl",
	Type:  "templated_string",
	Value: `"{{ %s }}"`,
	Children: []*ASTNode{
		{
			ID:    "node_percent_str",
			Type:  "string",
			Value: `"{{ %s }}"`,
		},
		{
			ID:    "node_msg_ident",
			Type:  "identifier",
			Value: "message",
		},
	},
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Avoid using %s for string formatting with untrusted input. Use safe templating engines or parameterized inputs.",
}

// Echo F-String Message
var EchoFStringMessage = &ASTNode{
	ID:    "node_fstring_echo",
	Type:  "f_string",
	Value: `f"echo {message}"`,
	Children: []*ASTNode{
		{
			ID:    "node_echo_str",
			Type:  "string",
			Value: "echo ",
		},
		{
			ID:    "node_msg_ident",
			Type:  "identifier",
			Value: "message",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid f-strings with user input in OS commands. Use subprocess with list arguments to prevent injection.",
}

// Empty Dictionary Assignment
var AttrEmptyDict = &ASTNode{
	ID:    "node_empty_dict",
	Type:  "assignment",
	Value: "empty_dict = {}",
	Children: []*ASTNode{
		{ID: "node_empty_dict_ident", Type: "identifier", Value: "empty_dict"},
		{ID: "node_empty_dict_value", Type: "dict", Value: "{}"},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure the dictionary is not populated with untrusted data later in the code.",
}

// Empty List Assignment
var AttrEmptyList = &ASTNode{
	ID:    "node_empty_list",
	Type:  "assignment",
	Value: "empty_list = []",
	Children: []*ASTNode{
		{ID: "node_empty_list_ident", Type: "identifier", Value: "empty_list"},
		{ID: "node_empty_list_value", Type: "list", Value: "[]"},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure the list is not populated with untrusted data later in the code.",
}

// Dictionary Creation
var AttrSomeDict = &ASTNode{
	ID:    "node_somedict",
	Type:  "assignment",
	Value: "somedict = dict()",
	Children: []*ASTNode{
		{ID: "node_somedict_ident", Type: "identifier", Value: "somedict"},
		{ID: "node_somedict_value", Type: "call", Value: "dict()"},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure the dictionary is not populated with untrusted data later in the code.",
}

// List Creation
var AttrSomeList = &ASTNode{
	ID:    "node_somelist",
	Type:  "assignment",
	Value: "somelist = list()",
	Children: []*ASTNode{
		{ID: "node_somelist_ident", Type: "identifier", Value: "somelist"},
		{ID: "node_somelist_value", Type: "call", Value: "list()"},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure the list is not populated with untrusted data later in the code.",
}

// Set Creation
var AttrSomeSet = &ASTNode{
	ID:    "node_someset",
	Type:  "assignment",
	Value: "someset = set()",
	Children: []*ASTNode{
		{ID: "node_someset_ident", Type: "identifier", Value: "someset"},
		{ID: "node_someset_value", Type: "call", Value: "set()"},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure the set is not populated with untrusted data later in the code.",
}

// Set Literal Assignment
var AttrMySet = &ASTNode{
	ID:    "node_myset",
	Type:  "assignment",
	Value: "myset = {1, 2, 3}",
	Children: []*ASTNode{
		{ID: "node_myset_ident", Type: "identifier", Value: "myset"},
		{ID: "node_myset_value", Type: "set", Value: "{1, 2, 3}"},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure the set is not populated with untrusted data later in the code.",
}

// Subprocess Exec with Args
var CreateSubprocessFromEventArgs = &ASTNode{
	ID:    "node_create_exec_args",
	Type:  "call",
	Value: "asyncio.subprocess.create_subprocess_exec(program, *args)",
	Children: []*ASTNode{
		{
			ID:    "node_create_func",
			Type:  "attribute",
			Value: "asyncio.subprocess.create_subprocess_exec",
		},
		{
			ID:    "node_args_unpack",
			Type:  "starred",
			Value: "*args",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Validate and sanitize all arguments before passing to subprocess. Use list-based arguments instead of string concatenation.",
}

// Subprocess Exec with Command
var CreateSubprocessFromEventCmd = &ASTNode{
	ID:    "node_create_exec_cmd",
	Type:  "call",
	Value: `asyncio.subprocess.create_subprocess_exec(program, [program, "-c", event['cmd']])`,
	Children: []*ASTNode{
		{
			ID:    "node_create_func2",
			Type:  "attribute",
			Value: "asyncio.subprocess.create_subprocess_exec",
		},
		{
			ID:    "node_list_args",
			Type:  "list",
			Value: `[program, "-c", event['cmd']]`,
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize event['cmd'] to prevent command injection. Prefer parameterized commands over user-controlled input.",
}

// Subprocess Exec with Lambda and Args
var SubprocessExecWithArgs = &ASTNode{
	ID:    "node_subprocess_exec_args",
	Type:  "call",
	Value: "loop.subprocess_exec(lambda: WaitingProtocol(exit_future), *args)",
	Children: []*ASTNode{
		{
			ID:    "node_method",
			Type:  "attribute",
			Value: "loop.subprocess_exec",
		},
		{
			ID:    "node_lambda_proto",
			Type:  "lambda",
			Value: "lambda: WaitingProtocol(exit_future)",
		},
		{
			ID:    "node_star_args",
			Type:  "starred",
			Value: "*args",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Validate and sanitize *args to prevent command injection. Use list-based arguments for subprocess calls.",
}

// Subprocess Exec with Command List
var SubprocessExecWithCmd = &ASTNode{
	ID:    "node_subprocess_exec_cmd",
	Type:  "call",
	Value: `loop.subprocess_exec(lambda: WaitingProtocol(exit_future), ["bash", "-c", cmd])`,
	Children: []*ASTNode{
		{
			ID:    "node_method2",
			Type:  "attribute",
			Value: "loop.subprocess_exec",
		},
		{
			ID:    "node_lambda_proto2",
			Type:  "lambda",
			Value: "lambda: WaitingProtocol(exit_future)",
		},
		{
			ID:    "node_cmd_list",
			Type:  "list",
			Value: `["bash", "-c", cmd]`,
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize 'cmd' to prevent command injection. Use parameterized inputs or avoid shell execution.",
}

// Loop Subprocess Shell
var LoopSubprocessShellEventCmd = &ASTNode{
	ID:    "node_loop_shell_cmd",
	Type:  "call",
	Value: "loop.subprocess_shell(lambda: WaitingProtocol(exit_future), event['cmd'])",
	Children: []*ASTNode{
		{
			ID:    "node_shell_func",
			Type:  "attribute",
			Value: "loop.subprocess_shell",
		},
		{
			ID:    "node_lambda_proto",
			Type:  "lambda",
			Value: "lambda: WaitingProtocol(exit_future)",
		},
		{
			ID:    "node_event_cmd",
			Type:  "subscript",
			Value: "event['cmd']",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid subprocess_shell with untrusted input. Use subprocess_exec with sanitized list arguments.",
}

// Asyncio Subprocess Shell
var AsyncioCreateShellEventCmd = &ASTNode{
	ID:    "node_asyncio_shell_cmd",
	Type:  "call",
	Value: "asyncio.subprocess.create_subprocess_shell(event['cmd'])",
	Children: []*ASTNode{
		{
			ID:    "node_shell_func2",
			Type:  "attribute",
			Value: "asyncio.subprocess.create_subprocess_shell",
		},
		{
			ID:    "node_event_cmd2",
			Type:  "subscript",
			Value: "event['cmd']",
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid create_subprocess_shell with user input. Use create_subprocess_exec with sanitized arguments.",
}

// OS Spawnlp
var SpawnlpEventCmd = &ASTNode{
	ID:    "node_spawnlp_event",
	Type:  "call",
	Value: "os.spawnlp(os.P_WAIT, event['cmd'])",
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnlp"},
		{ID: "node_arg", Type: "subscript", Value: "event['cmd']"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize event['cmd'] to prevent command injection. Prefer subprocess with list arguments.",
}

// OS Spawnlpe
var SpawnlpeEventCmd = &ASTNode{
	ID:    "node_spawnlpe_event",
	Type:  "call",
	Value: "os.spawnlpe(os.P_WAIT, event['cmd'])",
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnlpe"},
		{ID: "node_arg", Type: "subscript", Value: "event['cmd']"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize event['cmd'] to prevent command injection. Use subprocess with list arguments.",
}

// OS Spawnv F-String
var SpawnvFString = &ASTNode{
	ID:    "node_spawnv_fstring",
	Type:  "call",
	Value: `os.spawnv(os.P_WAIT, f"foo-{event['cmd']}")`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnv"},
		{ID: "node_arg", Type: "f_string", Value: `f"foo-{event['cmd']}"`},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid f-strings in spawnv arguments. Use sanitized list-based arguments with subprocess.",
}

// OS Spawnve
var SpawnveEventCmd = &ASTNode{
	ID:    "node_spawnve_event",
	Type:  "call",
	Value: `os.spawnve(os.P_WAIT, event['cmd'], ["-a"], os.environ)`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnve"},
		{ID: "node_arg", Type: "subscript", Value: "event['cmd']"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize event['cmd'] to prevent command injection. Use subprocess with list arguments.",
}

// OS Spawnve with Shell
var SpawnveWithShell = &ASTNode{
	ID:    "node_spawnve_shell",
	Type:  "call",
	Value: `os.spawnve(os.P_WAIT, "/bin/bash", ["-c", f"ls -la {event['cmd']}"], os.environ)`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnve"},
		{ID: "node_list_arg", Type: "list", Value: `["-c", f"ls -la {event['cmd']}"]`},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid shell execution with f-strings. Use subprocess with sanitized list arguments.",
}

// OS Spawnl F-String
var SpawnlFString = &ASTNode{
	ID:    "node_spawnl_fstring",
	Type:  "call",
	Value: `os.spawnl(os.P_WAIT, "/bin/bash", "-c", f"ls -la {event['cmd']}")`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnl"},
		{ID: "node_arg", Type: "f_string", Value: `f"ls -la {event['cmd']}"`},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid f-strings in spawnl arguments. Use subprocess with sanitized list arguments.",
}

// OS Spawnl Event Command
var SpawnlEventCmd = &ASTNode{
	ID:    "node_spawnl_event",
	Type:  "call",
	Value: `os.spawnl(os.P_WAIT, "/bin/bash", "-c", event['cmd'])`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "os.spawnl"},
		{ID: "node_arg", Type: "subscript", Value: "event['cmd']"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Sanitize event['cmd'] to prevent command injection. Use subprocess with list arguments.",
}

// Subprocess Call with Format Shell
var CallFormatShell = &ASTNode{
	ID:    "node_call_format_shell",
	Type:  "call",
	Value: `subprocess.call("grep -R {} .".format(event['id']), shell=True)`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "subprocess.call"},
		{ID: "node_format_str", Type: "call", Value: `"grep -R {} .".format(event['id'])`},
		{ID: "node_kwarg_shell", Type: "keyword", Value: "shell=True"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid shell=True with formatted strings. Use subprocess.call with list arguments and sanitize inputs.",
}

// Subprocess Call with Command List
var CallCmdListShell = &ASTNode{
	ID:    "node_call_list_shell",
	Type:  "call",
	Value: `subprocess.call([cmd[0], cmd[1], "some", "args"], shell=True)`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "subprocess.call"},
		{ID: "node_list_arg", Type: "list", Value: `[cmd[0], cmd[1], "some", "args"]`},
		{ID: "node_kwarg_shell", Type: "keyword", Value: "shell=True"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid shell=True. Sanitize cmd[0] and cmd[1] to prevent command injection.",
}

// Subprocess Call with CWD
var CallFormatShellCwd = &ASTNode{
	ID:    "node_call_format_shell_cwd",
	Type:  "call",
	Value: `subprocess.call("grep -R {} .".format(event['id']), shell=True, cwd="/home/user")`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "subprocess.call"},
		{ID: "node_kwarg_shell", Type: "keyword", Value: "shell=True"},
		{ID: "node_kwarg_cwd", Type: "keyword", Value: `cwd="/home/user"`},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid shell=True with formatted strings. Use list-based arguments and validate cwd path.",
}

// Subprocess Popen with Shell
var PopenWithShell = &ASTNode{
	ID:    "node_popen_shell",
	Type:  "call",
	Value: `subprocess.Popen([...], ..., shell=True)`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "subprocess.Popen"},
		{ID: "node_kwarg_shell", Type: "keyword", Value: "shell=True"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid shell=True in Popen. Use list-based arguments and sanitize all inputs.",
}

// Subprocess Popen with Shell and Text
var PopenShellText = &ASTNode{
	ID:    "node_popen_shell_text",
	Type:  "call",
	Value: `subprocess.Popen([...], ..., shell=True, text=True)`,
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "subprocess.Popen"},
		{ID: "node_kwarg_shell", Type: "keyword", Value: "shell=True"},
		{ID: "node_kwarg_text", Type: "keyword", Value: "text=True"},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid shell=True and text=True with untrusted input. Use list-based arguments and validate inputs.",
}

// OS System F-String
var OsSystemFStringDir = &ASTNode{
	ID:    "node_os_system_fstring",
	Type:  "call",
	Value: `os.system(f"ls -la {event['dir']}")`,
	Children: []*ASTNode{
		{
			ID:    "node_func",
			Type:  "attribute",
			Value: "os.system",
		},
		{
			ID:    "node_arg",
			Type:  "f_string",
			Value: `f"ls -la {event['dir']}"`,
		},
	},
	Message: "Vulnerability: CWE-78 (Improper Neutralization of Special Elements used in an OS Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid os.system with f-strings. Use subprocess with sanitized list arguments.",
}

// DynamoDB Query with Filter
var DynamoDBQueryWithFilter = &ASTNode{
	ID:    "node_dynamodb_query_filter",
	Type:  "call",
	Value: "dynamodb_table.query(QueryFilter = event.body.filter)",
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "dynamodb_table.query"},
		{ID: "node_kwarg", Type: "keyword", Value: "QueryFilter = event.body.filter"},
	},
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Validate and sanitize event.body.filter to prevent injection. Use parameterized queries or DynamoDB's expression APIs.",
}

// DynamoDB Scan with Filter
var DynamoDBScanWithFilter = &ASTNode{
	ID:    "node_dynamodb_scan_filter",
	Type:  "call",
	Value: "client.scan(ScanFilter = event.body.filter)",
	Children: []*ASTNode{
		{ID: "node_func", Type: "attribute", Value: "client.scan"},
		{ID: "node_kwarg", Type: "keyword", Value: "ScanFilter = event.body.filter"},
	},
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Sanitize event.body.filter and use DynamoDB's expression APIs to prevent injection.",
}

// MySQL SQLi Update Public IP
var MySQLSqliUpdatePublicIP = &ASTNode{
	ID:      "node_mysql_sqli_publicip",
	Type:    "call",
	Value:   "mydbCursor.execute(\"UPDATE `EC2ServerPublicIP` SET %s = '%s' WHERE %s = %s\", (\"publicIP\",publicIP,\"ID\", 1))",
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use parameterized queries with placeholders to prevent SQL injection. Avoid string formatting for SQL queries.",
}

// Psycopg2 SQLi Query
var Psycopg2SQLiQuery = &ASTNode{
	ID:      "node_psycopg2_sqli",
	Type:    "call",
	Value:   "cur.execute(findQuery)",
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use parameterized queries with placeholders instead of dynamic query strings.",
}

// Pymssql SQLi Query
var PymssqlSQLiQuery = &ASTNode{
	ID:      "node_pymssql_sqli",
	Type:    "call",
	Value:   "cursor.execute(query)",
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use parameterized queries to prevent SQL injection. Avoid executing untrusted query strings.",
}

// PyMySQL SQLi Query
var PyMySQLSqliQuery = &ASTNode{
	ID:      "node_pymysql_sqli_query",
	Type:    "call",
	Value:   "cur.execute(sql)",
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use parameterized queries with placeholders to prevent SQL injection.",
}

// SQLAlchemy SQLi Query
var SQLAlchemySqliQuery = &ASTNode{
	ID:    "node_sqlalchemy_sqli",
	Type:  "call",
	Value: `connection.execute(f"SELECT * FROM foobar WHERE id = '{event['id']}'")`,
	Children: []*ASTNode{
		{
			ID:    "node_func",
			Type:  "attribute",
			Value: "connection.execute",
		},
		{
			ID:    "node_arg",
			Type:  "f_string",
			Value: `f"SELECT * FROM foobar WHERE id = '{event['id']}'"`,
		},
	},
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use SQLAlchemy's parameterized queries or ORM methods to prevent SQL injection.",
}

// Exec Tainted Format
var ExecTaintedFormat = &ASTNode{
	ID:      "node_exec_tainted_format",
	Type:    "call",
	Value:   `exec(dynamic1.format(event['url']))`,
	Message: "Vulnerability: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid using exec() with untrusted input. Use safer alternatives like function calls or validated inputs.",
}

// Tainted HTML Response
var TaintedHTMLResponse = &ASTNode{
	ID:      "node_html_body_pair",
	Type:    "pair",
	Value:   "\"body\": html",
	Message: "Vulnerability: CWE-79 (Improper Neutralization of Input During Web Page Generation); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Sanitize HTML content using libraries like bleach or escape HTML special characters.",
}

// Pickle Load Exploit Code
var PickleLoadExploitCode = &ASTNode{
	ID:      "node_pickle_load",
	Type:    "call",
	Value:   "_pickle.load(event['exploit_code'])",
	Message: "Vulnerability: CWE-502 (Deserialization of Untrusted Data); OWASP Top 10: A08:2021 - Software and Data Integrity Failures; Severity: Critical; Recommendation: Avoid deserializing untrusted data with pickle. Use safe serialization formats like JSON.",
}

// CPickle Loads F-String
var CPickleLoadsFString = &ASTNode{
	ID:      "node_cpickle_loads_fstring",
	Type:    "call",
	Value:   `cPickle.loads(f"foobar{event['exploit_code']}")`,
	Message: "Vulnerability: CWE-502 (Deserialization of Untrusted Data); OWASP Top 10: A08:2021 - Software and Data Integrity Failures; Severity: Critical; Recommendation: Avoid cPickle.loads with untrusted input. Use JSON or other safe serialization formats.",
}

// Dill Loads Call
var DillLoadsCall = &ASTNode{
	ID:      "node_dill_loads_call",
	Type:    "call",
	Value:   "loads(event['exploit_code'])(123)",
	Message: "Vulnerability: CWE-502 (Deserialization of Untrusted Data); OWASP Top 10: A08:2021 - Software and Data Integrity Failures; Severity: Critical; Recommendation: Avoid deserializing untrusted data with dill. Use safe serialization formats like JSON.",
}

// Shelve Open F-String
var ShelveOpenFString = &ASTNode{
	ID:      "node_shelve_open_fstring",
	Type:    "call",
	Value:   `shelve.open(f"/tmp/path/{event['object_path']}")`,
	Message: "Vulnerability: CWE-73 (External Control of File Name or Path); OWASP Top 10: A01:2021 - Broken Access Control; Severity: High; Recommendation: Validate and sanitize event['object_path'] to prevent path traversal attacks. Use predefined paths.",
}

// Tainted SQL String Format
var TaintedSQLStringFormat = &ASTNode{
	ID:      "node_tainted_sql_format",
	Type:    "assignment",
	Value:   `sql = """UPDATE ` + "`EC2ServerPublicIP`" + ` SET %s = '%s' WHERE %s = %d""" % ("publicIP",publicIP,"ID", 1)`,
	Message: "Vulnerability: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use parameterized queries instead of string formatting to prevent SQL injection.",
}

// Bokeh Import WidgetBox
var BokehImportWidgetBox = &ASTNode{
	ID:      "node_bokeh_widgetbox",
	Type:    "import_from",
	Value:   "from bokeh.layouts import widgetbox",
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure Bokeh is used securely and validate any dynamic inputs in widgets.",
}

// Bokeh Import From Networkx
var BokehImportFromNetworkx = &ASTNode{
	ID:      "node_bokeh_from_networkx",
	Type:    "import_from",
	Value:   "from bokeh.models.graphs import from_networkx",
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Validate graph data inputs to prevent potential misuse in visualizations.",
}

// Bokeh WidgetBox Call
var BokehWidgetBoxCall = &ASTNode{
	ID:      "node_bokeh_widgetbox_call",
	Type:    "call",
	Value:   "widgetbox(children=[slider], sizing_mode='scale_width')",
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure slider inputs are validated to prevent injection in dynamic widgets.",
}

// Bokeh From Networkx Call
var BokehFromNetworkxCall = &ASTNode{
	ID:      "node_bokeh_from_networkx_call",
	Type:    "call",
	Value:   "from_networkx(G, nx.spring_layout, scale=0.5, center=(0,0))",
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Validate graph G to ensure it does not contain malicious data.",
}

// Boto3 Client Hardcoded Secret
var Boto3ClientHardcodedSecret = &ASTNode{
	ID:      "node_boto3_client_hardcoded_secret",
	Type:    "call",
	Value:   `client("s3", aws_secret_access_key="jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx")`,
	Message: "Vulnerability: CWE-798 (Use of Hard-coded Credentials); OWASP Top 10: A07:2021 - Identification and Authentication Failures; Severity: Critical; Recommendation: Use AWS Secrets Manager or environment variables for credentials. Avoid hardcoding secrets.",
}

// Boto3 Session Hardcoded Secret
var Boto3SessionHardcodedSecret = &ASTNode{
	ID:      "node_boto3_session_hardcoded_secret",
	Type:    "call",
	Value:   `boto3.sessions.Session(aws_secret_access_key="jWnyxxxxxxxxxxxxxxxxX7ZQxxxxxxxxxxxxxxxx")`,
	Message: "Vulnerability: CWE-798 (Use of Hard-coded Credentials); OWASP Top 10: A07:2021 - Identification and Authentication Failures; Severity: Critical; Recommendation: Store credentials securely using AWS Secrets Manager or environment variables.",
}

// Boto3 Sessions Session Hardcoded Key
var Boto3SessionsSessionHardcodedKey = &ASTNode{
	ID:      "node_boto3_sessions_session_hardcoded_key",
	Type:    "call",
	Value:   `s.Session(aws_access_key_id="AKIAxxxxxxxxxxxxxxxx")`,
	Message: "Vulnerability: CWE-798 (Use of Hard-coded Credentials); OWASP Top 10: A07:2021 - Identification and Authentication Failures; Severity: Critical; Recommendation: Use secure credential management like AWS Secrets Manager instead of hardcoding keys.",
}

// Boto3 Resource Hardcoded Key Secret
var Boto3ResourceHardcodedKeySecret = &ASTNode{
	ID:   "node_boto3_resource_hardcoded_key_secret",
	Type: "call",
	Value: `boto3.resource(
    "s3",
    aws_access_key_id=uhoh_key,
    aws_secret_access_key=ok_secret,
    region_name="sfo2",
    endpoint_url="https://sfo2.digitaloceanspaces.com",
)`,
	Message: "Vulnerability: CWE-798 (Use of Hard-coded Credentials); OWASP Top 10: A07:2021 - Identification and Authentication Failures; Severity: Critical; Recommendation: Avoid hardcoding AWS credentials. Use IAM roles or AWS Secrets Manager.",
}

// Boto3 Resource Hardcoded Secret
var Boto3ResourceHardcodedSecret = &ASTNode{
	ID:   "node_boto3_resource_hardcoded_secret",
	Type: "call",
	Value: `s3 = boto3.resource(
    "s3",
    aws_access_key_id=ok_key,
    aws_secret_access_key=uhoh_secret,
    region_name="sfo2",
    endpoint_url="https://sfo2.digitaloceanspaces.com",
)`,
	Message: "Vulnerability: CWE-798 (Use of Hard-coded Credentials); OWASP Top 10: A07:2021 - Identification and Authentication Failures; Severity: Critical; Recommendation: Use AWS Secrets Manager or environment variables for secure credential management.",
}

// Click Echo with Style
var ClickEchoWithStyle = &ASTNode{
	ID:    "node_click_echo_style",
	Type:  "call",
	Value: `click.echo(click.style("foo"))`,
	Children: []*ASTNode{
		{ID: "node_func_echo", Type: "attribute", Value: "click.echo"},
		{ID: "node_arg", Type: "call", Value: `click.style("foo")`},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Ensure styled output does not include untrusted data to prevent potential XSS if rendered in a web context.",
}

// Click Echo with Style and Color
var ClickEchoWithStyleColor = &ASTNode{
	ID:    "node_click_echo_style_color",
	Type:  "call",
	Value: `click.echo(click.style("foo", color="blue"))`,
	Children: []*ASTNode{
		{ID: "node_func_echo", Type: "attribute", Value: "click.echo"},
		{ID: "node_arg_style", Type: "call", Value: `click.style("foo", color="blue")`},
	},
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: Validate inputs if used in a web context to prevent XSS vulnerabilities.",
}

// Record and Zero Check
var RecordAndZeroCheck = &ASTNode{
	ID:    "node_check_is_none_explicit_1",
	Type:  "if_statement",
	Value: "if record and record == 0:\r\n    print(\"hello, this will never happen\")",
	Children: []*ASTNode{
		{ID: "node_condition", Type: "binary_operator", Value: "record and record == 0"},
	},
	Message: "Vulnerability: CWE-697 (Incorrect Comparison); OWASP Top 10: N/A; Severity: Medium; Recommendation: Use explicit None checks (e.g., `if record is not None`) to avoid logical errors in comparisons.",
}

// Attribute and Zero Check

// Attribute and Zero Check
var AttrAndZeroCheck = &ASTNode{
	ID:    "node_check_is_none_explicit_2",
	Type:  "if_statement",
	Value: "if record.a and record.a == 0:\r\n    print(\"Not reachable\")",
	Children: []*ASTNode{
		{
			ID:    "node_condition",
			Type:  "binary_operator",
			Value: "record.a and record.a == 0",
		},
	},
	Message: "Vulnerability: CWE-697 (Incorrect Comparison); OWASP Top 10: N/A; Severity: Medium; Recommendation: Use explicit None checks for attributes (e.g., `if record.a is not None`) to avoid logical errors.",
}

// Dictionary Attribute and Zero Check
var DictAttrAndZeroCheck = &ASTNode{
	ID:    "node_check_is_none_explicit_3",
	Type:  "if_statement",
	Value: "if record.a.get(\"H\") and record.a[\"H\"] == 0:\r\n    print(\"Not reachable\")",
	Children: []*ASTNode{
		{
			ID:    "node_condition",
			Type:  "binary_operator",
			Value: "record.a.get(\"H\") and record.a[\"H\"] == 0",
		},
	},
	Message: "Vulnerability: CWE-697 (Incorrect Comparison); OWASP Top 10: N/A; Severity: Medium; Recommendation: Use explicit None checks for dictionary access (e.g., `if record.a.get(\"H\") is not None`) to avoid logical errors.",
}

// Socket Shutdown Followed by Close
var ShutdownFollowedByClose = &ASTNode{
	ID:    "socket_shutdown_close_vuln",
	Type:  "try_statement",
	Value: "try:\n    shutdown\n    close",
	Children: []*ASTNode{
		{
			ID:    "node_shutdown",
			Type:  "expression_statement",
			Value: "shutdown",
		},
		{
			ID:    "node_close",
			Type:  "expression_statement",
			Value: "close",
		},
	},
	Message: "Vulnerability: CWE-404 (Improper Resource Shutdown or Release); OWASP Top 10: N/A; Severity: Medium; Recommendation: Ensure proper error handling around shutdown and close to prevent resource leaks. Verify socket state before closing.",
}

// Socket Shutdown Followed by Close 2
var ShutdownFollowedByClose2 = &ASTNode{
	ID:    "socket_shutdown_close_vuln",
	Type:  "try_statement",
	Value: "try:\n    shutdown\n    close",
	Children: []*ASTNode{
		{
			ID:    "node_shutdown_partial",
			Type:  "expression_statement",
			Value: "shutdown", // partial match
		},
		{
			ID:    "node_close_partial",
			Type:  "expression_statement",
			Value: "close", // partial match
		},
	},
	Message: "Vulnerability: CWE-404 (Improper Resource Shutdown or Release); OWASP Top 10: N/A; Severity: Medium; Recommendation: Ensure proper error handling around shutdown and close to prevent resource leaks. Verify socket state before closing.",
}

// Socket Shutdown Followed by Close 3
var ShutdownFollowedByClose3 = &ASTNode{
	ID:    "socket_shutdown_close_vuln",
	Type:  "try_statement",
	Value: "try:\n    sock.shutdown(socket.SHUT_RDWR)\n    sock.close()",
	Children: []*ASTNode{
		{
			ID:    "node_shutdown_specific",
			Type:  "expression_statement",
			Value: "sock.shutdown(socket.SHUT_RDWR)",
		},
		{
			ID:    "node_close_specific",
			Type:  "expression_statement",
			Value: "sock.close()",
		},
	},
	Message: "Vulnerability: CWE-404 (Improper Resource Shutdown or Release); OWASP Top 10: N/A; Severity: Medium; Recommendation: Ensure proper error handling around shutdown and close to prevent resource leaks. Verify socket state before closing.",
}
