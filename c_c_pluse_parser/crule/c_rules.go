package crule

type ASTNode struct {
	ID       string
	Type     string
	Value    string
	Children []*ASTNode
	Parent   *ASTNode
	Message  string // Added field to store vulnerability details
}

var VulnerableCNodes = []*ASTNode{
	CStringEqualityRule,
	CStrcmpEqual,
	DoubleGoto,
	AtoiUnsafe,
	AtolUnsafe,
	AtollUnsafe,
	UnsafeSscanfF,
	UnsafeSscanfLF,
	UnsafeSscanfLLF,
	UnsafeSscanfLdF,
	UnsafeSscanfD,
	DoubleFree,
	UseAfterFree_Strcpy,
	UseAfterFree_IndirectFuncCall,
	UseAfterFree_OtherFunc1,
	UseAfterFree_OtherFunc2,
	UseAfterFree_OtherFunc3,
	UseAfterFree_OtherFunc4,
	UseAfterFree_OtherFunc5,
	InfoLeakPrintfDirect,
	InsecureUseGets,
	InsecureMemsetPassword,
	InsecureMemsetToken,
	InsecureMemsetSPassword,
	InsecureMemsetSToken,
	InsecurePrintfArgv2,
	InsecurePrintfFormatCopied,
	InsecureSprintfArgv,
	InsecureSprintfCopiedFormat,
	InsecureVsprintfArgv,
	InsecureVsprintfCopiedFormat,
	InsecureScanfWithStringFormat,
	InsecureUseStrcat,
	InsecureUseStrncat,
	InsecureUseStrcpy,
	InsecureUseStrncpy,
	InsecureUseStrtok,
	RandomFDExhaustion1,
	RandomFDExhaustion2,
	UseAfterFreeCall,
	UseAfterFreeFieldAccess,
	UseAfterFreePointerAccess,
}

// Vulnerable C string equality using '=='
var CStringEqualityRule = &ASTNode{
	ID:      "c-string-equality",
	Type:    "binary_expression",
	Value:   `s == "World"`,
	Message: "Vulnerability: CWE-480 (Use of Incorrect Operator); OWASP Top 10: N/A; Severity: Medium; Recommendation: Use strcmp() to compare C strings instead of '==' to avoid incorrect pointer comparison.",
}

// String comparison with strcmp
var CStrcmpEqual = &ASTNode{
	ID:      "node_c_string_equality_1",
	Type:    "binary_expression",
	Value:   `strcmp(s, "World") == 0`,
	Message: "Vulnerability: None; OWASP Top 10: N/A; Severity: Low; Recommendation: This is a correct usage of strcmp() for string comparison. Ensure inputs are null-terminated to avoid undefined behavior.",
}

// Double goto statement
var DoubleGoto = &ASTNode{
	ID:      "node_double_goto",
	Type:    "goto_statement",
	Value:   "goto ONE;",
	Message: "Vulnerability: CWE-691 (Insufficient Control Flow Management); OWASP Top 10: N/A; Severity: Medium; Recommendation: Avoid using goto statements as they can lead to spaghetti code. Use structured control flow (e.g., loops, conditionals) instead.",
}

// Unsafe use of atoi
var AtoiUnsafe = &ASTNode{
	ID:      "incorrect-use-ato-fn",
	Type:    "call_expression",
	Value:   "atoi(buf)",
	Message: "Vulnerability: CWE-190 (Integer Overflow or Wraparound); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtol() or similar functions to safely parse integers and check for errors to prevent undefined behavior.",
}

// Unsafe use of atol
var AtolUnsafe = &ASTNode{
	ID:      "incorrect-use-ato-fn",
	Type:    "call_expression",
	Value:   "atol(buf)",
	Message: "Vulnerability: CWE-190 (Integer Overflow or Wraparound); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtol() or strtoll() for safe integer parsing with error handling to avoid undefined behavior.",
}

// Unsafe use of atoll
var AtollUnsafe = &ASTNode{
	ID:      "incorrect-use-ato-fn",
	Type:    "call_expression",
	Value:   "atoll(buf)",
	Message: "Vulnerability: CWE-190 (Integer Overflow or Wraparound); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtoll() for safe long long integer parsing with error handling to prevent undefined behavior.",
}

// Unsafe sscanf with %f
var UnsafeSscanfF = &ASTNode{
	ID:      "incorrect-use-sscanf-fn",
	Type:    "call_expression",
	Value:   `sscanf(float_str, "%f", &f)`,
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Validate input and use safer parsing functions like strtof() to avoid buffer overflows or undefined behavior.",
}

// Unsafe sscanf with %lf
var UnsafeSscanfLF = &ASTNode{
	ID:      "incorrect-use-sscanf-fn",
	Type:    "call_expression",
	Value:   `sscanf(float_str, "%lf", &d)`,
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtod() for safe double parsing and validate input to prevent undefined behavior.",
}

// Unsafe sscanf with %llf
var UnsafeSscanfLLF = &ASTNode{
	ID:      "incorrect-use-sscanf-fn",
	Type:    "call_expression",
	Value:   `sscanf(float_str, "%llf", &ld)`,
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtold() for safe long double parsing and validate input to avoid undefined behavior.",
}

// Unsafe sscanf with %Lf
var UnsafeSscanfLdF = &ASTNode{
	ID:      "incorrect-use-sscanf-fn",
	Type:    "call_expression",
	Value:   `sscanf(float_str, "%Lf", &ld)`,
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtold() for safe long double parsing and validate input to prevent undefined behavior.",
}

// Unsafe sscanf with %d
var UnsafeSscanfD = &ASTNode{
	ID:      "incorrect-use-sscanf-fn",
	Type:    "call_expression",
	Value:   `sscanf(int_str, "%d", &i)`,
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strtol() for safe integer parsing and validate input to prevent undefined behavior.",
}

// Double free vulnerability
var DoubleFree = &ASTNode{
	ID:      "double-free",
	Type:    "call_expression",
	Value:   "free(var)",
	Message: "Vulnerability: CWE-415 (Double Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Ensure memory is freed only once by setting pointers to NULL after free() and using memory management checks.",
}

// Use-after-free with strcpy
var UseAfterFree_Strcpy = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "strcpy(buf, (char*)var)",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Ensure pointers are not used after being freed. Set pointers to NULL after free() and validate pointer usage.",
}

// Use-after-free with indirect function call
var UseAfterFree_IndirectFuncCall = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "var->func(var->myname)",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Verify pointer validity before use and set pointers to NULL after free() to prevent use-after-free.",
}

// Use-after-free with other_func
var UseAfterFree_OtherFunc1 = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "other_func((char*)(*var))",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Ensure pointers are valid before passing to functions. Set pointers to NULL after free().",
}

// Use-after-free with other_func
var UseAfterFree_OtherFunc2 = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "other_func((char*)var[0])",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Validate array elements before use and set pointers to NULL after free() to avoid use-after-free.",
}

// Use-after-free with other_func
var UseAfterFree_OtherFunc3 = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "other_func((char*)var)",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Check pointer validity before use and set pointers to NULL after free() to prevent use-after-free.",
}

// Use-after-free with other_func
var UseAfterFree_OtherFunc4 = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "other_func((char*)var->myname)",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Ensure struct fields are valid before use and set pointers to NULL after free().",
}

// Use-after-free with other_func
var UseAfterFree_OtherFunc5 = &ASTNode{
	ID:      "function-use-after-free",
	Type:    "call_expression",
	Value:   "other_func((char*)*var)",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Validate dereferenced pointers before use and set pointers to NULL after free().",
}

// Use-after-free with function call
var UseAfterFreeCall = &ASTNode{
	ID:      "use-after-free",
	Type:    "call_expression",
	Value:   "var->func(\"use after free\")",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Ensure pointers are not used after being freed. Set pointers to NULL after free() to prevent use-after-free.",
}

// Use-after-free with field access
var UseAfterFreeFieldAccess = &ASTNode{
	ID:      "use-after-free",
	Type:    "field_expression",
	Value:   "var->auth",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Validate struct pointers before accessing fields and set pointers to NULL after free().",
}

// Use-after-free with pointer access
var UseAfterFreePointerAccess = &ASTNode{
	ID:      "use-after-free",
	Type:    "unary_expression",
	Value:   "*var",
	Message: "Vulnerability: CWE-416 (Use After Free); OWASP Top 10: A09:2021 - Security Logging and Monitoring Failures; Severity: Critical; Recommendation: Check pointer validity before dereferencing and set pointers to NULL after free().",
}

// Information leak via printf
var InfoLeakPrintfDirect = &ASTNode{
	ID:      "info-leak-on-non-formated-string",
	Type:    "call_expression",
	Value:   "printf(argv[1])",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use fixed format strings in printf() to prevent format string vulnerabilities (e.g., printf(\"%s\", argv[1])).",
}

// Insecure use of gets
var InsecureUseGets = &ASTNode{
	ID:      "insecure-use-gets-fn",
	Type:    "call_expression",
	Value:   "gets(str)",
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Replace gets() with fgets() to prevent buffer overflows by specifying buffer size.",
}

// Insecure memset for password
var InsecureMemsetPassword = &ASTNode{
	ID:      "insecure-use-memset",
	Type:    "call_expression",
	Value:   "memset(password, ' ', strlen(password))",
	Message: "Vulnerability: CWE-14 (Compiler Removal of Code to Clear Buffers); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Use secure memory clearing functions like explicit_bzero() or memset_s() with proper size to ensure sensitive data is erased.",
}

// Insecure memset for token
var InsecureMemsetToken = &ASTNode{
	ID:      "insecure-use-memset",
	Type:    "call_expression",
	Value:   "memset(token, ' ', strlen(localBuffer))",
	Message: "Vulnerability: CWE-14 (Compiler Removal of Code to Clear Buffers); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Use secure memory clearing functions like explicit_bzero() or memset_s() with correct buffer size for sensitive data.",
}

// Insecure memset_s for password
var InsecureMemsetSPassword = &ASTNode{
	ID:      "insecure-use-memset",
	Type:    "call_expression",
	Value:   "memset_s(password, ' ', strlen(password))",
	Message: "Vulnerability: CWE-14 (Compiler Removal of Code to Clear Buffers); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Ensure memset_s() uses correct buffer size (not a character) and consider explicit_bzero() for secure memory clearing.",
}

// Insecure memset_s for token
var InsecureMemsetSToken = &ASTNode{
	ID:      "insecure-use-memset",
	Type:    "call_expression",
	Value:   "memset_s(token, ' ', strlen(localBuffer))",
	Message: "Vulnerability: CWE-14 (Compiler Removal of Code to Clear Buffers); OWASP Top 10: A02:2021 - Cryptographic Failures; Severity: High; Recommendation: Use memset_s() with correct size parameter and consider explicit_bzero() for secure memory clearing of sensitive data.",
}

// Insecure printf with argv
var InsecurePrintfArgv2 = &ASTNode{
	ID:      "insecure-use-printf-fn",
	Type:    "call_expression",
	Value:   "printf(argv[2], 1234)",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Avoid using user-controlled input as format strings. Use fixed format strings (e.g., printf(\"%s\", argv[2])).",
}

// Insecure printf with copied format
var InsecurePrintfFormatCopied = &ASTNode{
	ID:      "insecure-use-printf-fn",
	Type:    "call_expression",
	Value:   "printf(format, 1234)",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Validate or use fixed format strings to prevent format string vulnerabilities.",
}

// Insecure sprintf with argv
var InsecureSprintfArgv = &ASTNode{
	ID:      "insecure-use-printf-fn",
	Type:    "call_expression",
	Value:   "sprintf(buffer, argv[2], a, b, c)",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use snprintf() with fixed format strings to prevent format string attacks and buffer overflows.",
}

// Insecure sprintf with copied format
var InsecureSprintfCopiedFormat = &ASTNode{
	ID:      "insecure-use-printf-fn",
	Type:    "call_expression",
	Value:   "sprintf(buffer, format, a, b, c)",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use snprintf() with validated or fixed format strings to avoid format string vulnerabilities.",
}

// Insecure vsprintf with argv
var InsecureVsprintfArgv = &ASTNode{
	ID:      "insecure-use-printf-fn",
	Type:    "call_expression",
	Value:   "vsprintf(buffer, argv[1], args)",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use vsnprintf() with fixed format strings to prevent format string attacks and buffer overflows.",
}

// Insecure vsprintf with copied format
var InsecureVsprintfCopiedFormat = &ASTNode{
	ID:      "insecure-use-printf-fn",
	Type:    "call_expression",
	Value:   "vsprintf(buffer,format, args)",
	Message: "Vulnerability: CWE-134 (Use of Externally-Controlled Format String); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use vsnprintf() with validated format strings to prevent format string vulnerabilities.",
}

// Insecure scanf with string format
var InsecureScanfWithStringFormat = &ASTNode{
	ID:      "insecure-use-scanf-fn",
	Type:    "call_expression",
	Value:   `scanf("%s", str)`,
	Message: "Vulnerability: CWE-120 (Buffer Copy without Checking Size of Input); OWASP Top 10: A03:2021 - Injection; Severity: Critical; Recommendation: Use fgets() or scanf() with width specifiers (e.g., scanf(\"%99s\", str)) to prevent buffer overflows.",
}

// Insecure use of strcat
var InsecureUseStrcat = &ASTNode{
	ID:      "insecure-use-strcat-fn",
	Type:    "call_expression",
	Value:   "strcat(dst, src)",
	Message: "Vulnerability: CWE-120 (Buffer Copy without Checking Size of Input); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strncat() with proper size checks to prevent buffer overflows.",
}

// Insecure use of strncat
var InsecureUseStrncat = &ASTNode{
	ID:      "insecure-use-strcat-fn",
	Type:    "call_expression",
	Value:   "strncat(dst, src, 100)",
	Message: "Vulnerability: CWE-120 (Buffer Copy without Checking Size of Input); OWASP Top 10: A03:2021 - Injection; Severity: Medium; Recommendation: Ensure strncat’s size parameter is correctly calculated to avoid off-by-one errors and buffer overflows.",
}

// Insecure use of strcpy
var InsecureUseStrcpy = &ASTNode{
	ID:      "insecure-use-string-copy",
	Type:    "call_expression",
	Value:   "strcpy(dst, src)",
	Message: "Vulnerability: CWE-120 (Buffer Copy without Checking Size of Input); OWASP Top 10: A03:2021 - Injection; Severity: High; Recommendation: Use strncpy() with proper size checks to prevent buffer overflows.",
}

// Insecure use of strncpy
var InsecureUseStrncpy = &ASTNode{
	ID:      "insecure-use-string-copy",
	Type:    "call_expression",
	Value:   "strncpy(dst, src, 100)",
	Message: "Vulnerability: CWE-120 (Buffer Copy without Checking Size of Input); OWASP Top 10: A03:2021 - Injection; Severity: Medium; Recommendation: Ensure strncpy’s size parameter prevents buffer overflows and null-terminates the destination string.",
}

// Insecure use of strtok
var InsecureUseStrtok = &ASTNode{
	ID:      "insecure-use-strtok-fn",
	Type:    "call_expression",
	Value:   "strtok(str, \" \")",
	Message: "Vulnerability: CWE-676 (Use of Potentially Dangerous Function); OWASP Top 10: N/A; Severity: Medium; Recommendation: Use safer alternatives like strtok_r() to avoid thread-safety issues and unexpected string modifications.",
}

// Random FD exhaustion with read
var RandomFDExhaustion1 = &ASTNode{
	ID:      "random-fd-exhaustion",
	Type:    "call_expression",
	Value:   "read(fd, buf, sizeof(buf))",
	Message: "Vulnerability: CWE-400 (Uncontrolled Resource Consumption); OWASP Top 10: N/A; Severity: Medium; Recommendation: Validate file descriptors and limit resource usage to prevent file descriptor exhaustion.",
}

// Random FD exhaustion with read
var RandomFDExhaustion2 = &ASTNode{
	ID:      "random-fd-exhaustion",
	Type:    "call_expression",
	Value:   "read(fd, buf, 16)",
	Message: "Vulnerability: CWE-400 (Uncontrolled Resource Consumption); OWASP Top 10: N/A; Severity: Medium; Recommendation: Check file descriptor validity and implement resource limits to avoid exhaustion.",
}
