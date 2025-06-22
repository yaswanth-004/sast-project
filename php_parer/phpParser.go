package phpParser

import (
	"context"
	"log"
	"strings"

	phprules "sasttoolproject/php_parer/php_rules"

	"github.com/google/uuid"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/php"
)

type Pos struct {
	Line   int
	Column int
}

type ASTNode struct {
	ID       string
	Type     string
	Value    string
	Children []*ASTNode
	Parent   *ASTNode
	PosStart Pos
	PosEnd   Pos
}

type AnalysisContext struct {
	FileName    string
	NodeTable   []*ASTNode
	SourceLines []string // <-- ADD THIS LINE
}

func ParsePHPSource(path string, code string) {
	parser := sitter.NewParser()
	parser.SetLanguage(php.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, []byte(code))
	if err != nil {
		log.Printf("Error parsing PHP code: %v\n", err)
		return
	}

	rootNode := tree.RootNode()
	ast := buildAST(rootNode, code, nil)

	ctx := &AnalysisContext{
		FileName:    path,
		NodeTable:   flattenAST(ast),
		SourceLines: strings.Split(code, "\n"), // <-- ADD THIS
	}

	log.Printf("PHP AST parsing complete for: %s\n", path)
	ReportVulnerabilities(ctx, code)

}

func buildAST(n *sitter.Node, src string, parent *ASTNode) *ASTNode {
	node := &ASTNode{
		ID:     uuid.New().String(),
		Type:   n.Type(),
		Value:  strings.TrimSpace(n.Content([]byte(src))),
		Parent: parent,
		PosStart: Pos{
			Line:   int(n.StartPoint().Row) + 1,
			Column: int(n.StartPoint().Column) + 1,
		},
		PosEnd: Pos{
			Line:   int(n.EndPoint().Row) + 1,
			Column: int(n.EndPoint().Column) + 1,
		},
	}

	for i := 0; i < int(n.ChildCount()); i++ {
		child := buildAST(n.Child(i), src, node)
		node.Children = append(node.Children, child)
	}

	return node
}

func flattenAST(root *ASTNode) []*ASTNode {
	var nodes []*ASTNode
	var collect func(n *ASTNode)
	collect = func(n *ASTNode) {
		nodes = append(nodes, n)
		for _, child := range n.Children {
			collect(child)
		}
	}
	collect(root)
	return nodes
}
func ReportVulnerabilities(ctx *AnalysisContext, code string) {
	parsedIndex := make(map[string]*ASTNode)

	// Build index of nodes for efficient matching
	for _, node := range ctx.NodeTable {
		key := node.Type + "|" + node.Value
		parsedIndex[key] = node

		// Debug logging for specific node types
		if node.Type == "call_expression" {
			log.Printf("[DEBUG] call_expression: %q\n", node.Value)
		} else if node.Type == "if_statement" {
			log.Printf("[DEBUG] if_statement: %q\n", node.Value)
		}
	}

	// Check for vulnerabilities
	for _, node := range ctx.NodeTable {
		for _, vuln := range phprules.VulnerablePHPNodes {
			// Extract severity from message
			severity := "Unknown"
			if strings.Contains(vuln.Message, "Severity: ") {
				parts := strings.Split(vuln.Message, "Severity: ")
				if len(parts) > 1 {
					severityParts := strings.Split(parts[1], ";")
					severity = strings.TrimSpace(severityParts[0])
				}
			}

			if node.Type == vuln.Type && vuln.Type == "function_call_expression" && vuln.ID == "sha224-hash" {
				// Handle sha224-based hashes
				if strings.Contains(node.Value, "'sha224") ||
					strings.Contains(node.Value, "\"sha224") ||
					strings.Contains(node.Value, "'sha512/224") ||
					strings.Contains(node.Value, "\"sha512/224") ||
					strings.Contains(node.Value, "'sha3-224") ||
					strings.Contains(node.Value, "\"sha3-224") {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && (vuln.Type == "echo_statement" || vuln.Type == "expression_statement") &&
				(vuln.ID == "echoed-request" || vuln.ID == "printed-request") {
				// Handle input-reflecting sinks (echo/print)
				if strings.HasPrefix(strings.TrimSpace(node.Value), vuln.Value) && containsUserInput(node.Value) && !isSanitized(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == "call_expression" && vuln.Type == "function_call" && vuln.ID == "tainted-callable" {
				// Handle tainted-callable (usort with user input)
				if strings.Contains(node.Value, vuln.Value) && containsUserInput(node.Value) && !isSafeCallable(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "function_call_expression" && vuln.ID == "assert-use-audit" {
				// Handle assert-use-audit
				if !(strings.Contains(node.Value, ">") || strings.Contains(node.Value, "<") ||
					strings.Contains(node.Value, "!=") || strings.Contains(node.Value, "==") ||
					strings.Contains(node.Value, "instanceof")) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && strings.Contains(node.Value, vuln.Value) {
				// General case for other rules (e.g., eval, empty-with-boolean)
				log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
					vuln.ID, vuln.Type, node.Value,
					node.PosStart.Line, node.PosStart.Column,
					node.PosEnd.Line, node.PosEnd.Column,
					severity, vuln.Message)
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "tainted-exec" {
				// Handle tainted-exec (system/proc_open with unsanitized user input)
				if (strings.Contains(node.Value, "system") || strings.Contains(node.Value, "proc_open")) &&
					containsUserInput(node.Value) && !isCommandSanitized(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "tainted-filename" {
				// Handle tainted-filename (hash_file/file with unsanitized user input)
				if (strings.Contains(node.Value, "hash_file") || strings.Contains(node.Value, "file")) &&
					containsUserInput(node.Value) && !isFilenameSanitized(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "object_creation_expression" && vuln.ID == "tainted-object-instantiation" {
				// Handle tainted-object-instantiation (dynamic new with user input)
				if containsUserInput(node.Value) && !isSafeClassName(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "tainted-sql-string" {
				// Handle tainted-sql-string (mysql_query with unsanitized user input)
				if strings.Contains(node.Value, "mysql_query") && containsUserInput(node.Value) && !isSQLSanitized(node.Value, ctx.SourceLines, node) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "tainted-url-host" {
				// Handle tainted-url-host (curl_init with unsanitized user input in URL host)
				if strings.Contains(node.Value, "curl_init") && containsUserInput(node.Value) && isTaintedURLHost(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "eval-use" {
				// Handle eval-use (eval with user-controlled input)
				if strings.Contains(node.Value, "eval") && containsUserInput(node.Value) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "exec-use" {
				// Handle exec-use
				if strings.Contains(node.Value, "exec") ||
					strings.Contains(node.Value, "passthru") ||
					strings.Contains(node.Value, "proc_open") ||
					strings.Contains(node.Value, "popen") ||
					strings.Contains(node.Value, "shell_exec") ||
					strings.Contains(node.Value, "system") ||
					strings.Contains(node.Value, "pcntl_exec") {
					if containsUserInput(node.Value) && !isCommandSanitized(node.Value) {
						log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
							vuln.ID, vuln.Type, node.Value,
							node.PosStart.Line, node.PosStart.Column,
							node.PosEnd.Line, node.PosEnd.Column,
							severity, vuln.Message)
					}
				}
			} else if node.Type == vuln.Type && vuln.Type == "include_statement" && vuln.ID == "file-inclusion" {
				// Handle file-inclusion (include/require with user input)
				if (strings.Contains(node.Value, "include") ||
					strings.Contains(node.Value, "include_once") ||
					strings.Contains(node.Value, "require") ||
					strings.Contains(node.Value, "require_once")) &&
					containsUserInput(node.Value) && !strings.Contains(node.Value, "include_safe") {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "mcrypt-use" {
				// Handle mcrypt-use (deprecated mcrypt functions)
				if strings.Contains(node.Value, "mcrypt_ecb") ||
					strings.Contains(node.Value, "mcrypt_create_iv") ||
					strings.Contains(node.Value, "mdecrypt_generic") {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "binary_expression" && vuln.ID == "md5-loose-equality" {
				// Handle md5-loose-equality (loose equality with md5 or md5_file)
				if strings.Contains(node.Value, "==") && !strings.Contains(node.Value, "===") &&
					(strings.Contains(node.Value, "md5(") || strings.Contains(node.Value, "md5_file(")) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "md5-used-as-password" {
				// Handle md5-used-as-password
				if strings.Contains(node.Value, "setPassword") {
					// Check if the argument is derived from md5 or hash('md5', ...)
					if strings.Contains(node.Value, "md5(") || strings.Contains(node.Value, "hash('md5'") || strings.Contains(node.Value, "hash(\"md5\"") {
						log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
							vuln.ID, vuln.Type, node.Value,
							node.PosStart.Line, node.PosStart.Column,
							node.PosEnd.Line, node.PosEnd.Column,
							severity, vuln.Message)
					} else {
						// Check preceding nodes for md5 or hash('md5', ...) assignments
						for _, prevNode := range ctx.NodeTable {
							if prevNode.Type == "assignment_expression" &&
								(strings.Contains(prevNode.Value, "md5(") || strings.Contains(prevNode.Value, "hash('md5'") || strings.Contains(prevNode.Value, "hash(\"md5\"")) &&
								strings.Contains(node.Value, prevNode.Value[:strings.Index(prevNode.Value, "=")]) {
								log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
									vuln.ID, vuln.Type, node.Value,
									node.PosStart.Line, node.PosStart.Column,
									node.PosEnd.Line, node.PosEnd.Column,
									severity, vuln.Message)
								break
							}
						}
					}
				}
			} else if node.Type == vuln.Type && vuln.Type == "call_expression" && vuln.ID == "weak-crypto" {
				// Handle weak-crypto
				if strings.Contains(node.Value, "crypt") ||
					strings.Contains(node.Value, "md5(") ||
					strings.Contains(node.Value, "md5_file(") ||
					strings.Contains(node.Value, "sha1(") ||
					strings.Contains(node.Value, "sha1_file(") ||
					strings.Contains(node.Value, "str_rot13(") ||
					(strings.Contains(node.Value, "hash(") &&
						(strings.Contains(node.Value, "'md5'") || strings.Contains(node.Value, "\"md5\"") ||
							strings.Contains(node.Value, "'sha1'") || strings.Contains(node.Value, "\"sha1\""))) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nPosition: Line %d:%d → %d:%d\nSeverity: %s\nDetails: %s\n\n",
						vuln.ID, vuln.Type, node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						severity, vuln.Message)
				}
			}

		}
	}

}
func isTaintedURLHost(val string) bool {
	// Check for URL starting with https:// followed by user input
	if strings.HasPrefix(strings.ToLower(val), "https://") {
		// Split on first /
		parts := strings.SplitN(val[8:], "/", 2) // Skip https://
		if len(parts) > 0 {
			host := parts[0]
			// Unsafe if host contains user input and no static prefix
			return containsUserInput(host) && !strings.Contains(host, ".")
		}
	}
	return false
}

func isFilenameSanitized(val string) bool {
	sanitizers := []string{
		"basename(",
	}
	for _, s := range sanitizers {
		if strings.Contains(val, s) {
			return true
		}
	}
	return false
}
func isCommandSanitized(val string) bool {
	sanitizers := []string{
		"escapeshellarg(", "escapeshellcmd(",
	}
	for _, s := range sanitizers {
		if strings.Contains(val, s) {
			return true
		}
	}
	return false
}
func isSafeCallable(val string) bool {
	// Assume a safe callable is a constant function name like 'strcmp' or a lambda/closure
	safeCallables := []string{
		"'strcmp'", `"strcmp"`, "function(", "fn(", // PHP closures
	}
	for _, s := range safeCallables {
		if strings.Contains(val, s) {
			return true
		}
	}
	return false
}

func containsUserInput(val string) bool {
	lowered := strings.ToLower(val)
	return strings.Contains(lowered, "$_get") ||
		strings.Contains(lowered, "$_post") ||
		strings.Contains(lowered, "$_request") ||
		strings.Contains(lowered, "$_server") ||
		strings.Contains(lowered, "$_cookie")
}
func isSQLSanitized(val string, sourceLines []string, node *ASTNode) bool {
	sanitizers := []string{
		"mysqli_real_escape_string(",
	}
	for _, s := range sanitizers {
		if strings.Contains(val, s) {
			return true
		}
	}
	// Check source lines for sanitization of variables used in the query
	for _, line := range sourceLines {
		if strings.Contains(line, "mysqli_real_escape_string(") && strings.Contains(line, node.Value) {
			return true
		}
	}
	return false
}
func isSafeClassName(val string) bool {
	// Static class names (no $) or trusted names are safe
	return !strings.Contains(val, "$") || strings.Contains(val, "MyController")
}

func isSanitized(val string) bool {
	sanitizers := []string{
		"htmlentities(", "htmlspecialchars(", "esc_attr(", "e(", "isset(", "empty(",
	}
	for _, s := range sanitizers {
		if strings.Contains(val, s) {
			return true
		}
	}
	return false
}
