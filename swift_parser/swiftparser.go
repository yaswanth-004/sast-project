package swiftparser

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"

	swiftrule "sasttoolproject/swift_parser/rule"

	ts "github.com/smacker/go-tree-sitter"
	swift "github.com/smacker/go-tree-sitter/swift"
)

// Position represents a location in the source code
type Position struct {
	Line   int
	Column int
}

// ASTNode represents a node in the Abstract Syntax Tree
type ASTNode struct {
	ID        string
	Type      string
	Value     string
	PosStart  Position
	PosEnd    Position
	Children  []*ASTNode
	Parent    *ASTNode
	IsIgnored bool
}

// AnalysisContext holds the parsing context
type AnalysisContext struct {
	RootAST   *ASTNode
	FileInfo  *FileInfo
	NodeTable map[string]*ASTNode
	mu        sync.Mutex
}

// FileInfo contains metadata about the analyzed file
type FileInfo struct {
	Path       string
	FileName   string
	SourceCode []byte // Add this field
}

// ParseSwiftSource is the entry function to parse and analyze Swift code
func ParseSwiftSource(path string, code string) {
	ctx, err := AnalyzeSwiftCode(path, code)
	if err != nil {
		log.Printf("Swift Analysis failed on %s: %v\n", path, err)
		return
	}
	log.Printf("Swift AST parsing complete for: %s\n", ctx.FileInfo.FileName)
	ReportVulnerabilities(ctx)
}

// AnalyzeSwiftCode parses the Swift code and builds the AST
func AnalyzeSwiftCode(path string, code string) (*AnalysisContext, error) {
	ctx := &AnalysisContext{
		FileInfo:  &FileInfo{Path: path, FileName: filepath.Base(path), SourceCode: []byte(code)},
		NodeTable: make(map[string]*ASTNode),
	}
	rootNode, err := parseSwift(code, ctx)
	if err != nil {
		return nil, fmt.Errorf("swift parsing failed: %w", err)
	}
	ctx.RootAST = rootNode
	return ctx, nil
}

// parseSwift parses the Swift code using tree-sitter
func parseSwift(code string, ctx *AnalysisContext) (*ASTNode, error) {
	parser := ts.NewParser()
	parser.SetLanguage(swift.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(code))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Swift code: %v", err)
	}
	skipLines := extractSkipLines(code)
	return buildAST(tree.RootNode(), nil, ctx, []byte(code), skipLines), nil
}

// extractSkipLines identifies lines with // okid: comments
func extractSkipLines(source string) map[int][]string {
	lines := strings.Split(source, "\n")
	skipMap := make(map[int][]string)
	for i, line := range lines {
		if strings.Contains(line, "// okid:") {
			parts := strings.Split(line, "// okid:")
			if len(parts) > 1 {
				ruleIDs := strings.Fields(parts[1])
				skipMap[i+1] = ruleIDs // 1-based line numbers
				log.Printf("[DEBUG] Found skip comment '// okid: %v' at line %d", ruleIDs, i+1)
			}
		}
	}
	return skipMap
}

// buildAST constructs the AST from tree-sitter nodes
func buildAST(tsNode *ts.Node, parent *ASTNode, ctx *AnalysisContext, source []byte, skipLines map[int][]string) *ASTNode {
	if tsNode == nil || len(source) == 0 {
		return nil
	}
	startByte := tsNode.StartByte()
	endByte := tsNode.EndByte()
	if startByte >= uint32(len(source)) || endByte > uint32(len(source)) || startByte > endByte {
		return nil
	}
	content := string(source[startByte:endByte])
	startPoint := tsNode.StartPoint()
	endPoint := tsNode.EndPoint()
	startLine := int(startPoint.Row) + 1

	isIgnored := false
	if ruleIDs, ok := skipLines[startLine]; ok {
		for _, ruleID := range ruleIDs {
			if ruleID == "insecure-random" || ruleID == "swift-user-defaults" ||
				ruleID == "swift-potential-sqlite-injection" || ruleID == "swift-webview-config-allows-js-open-windows" {
				isIgnored = true
				break
			}
		}
	}

	node := &ASTNode{
		ID:        generateNodeID(ctx),
		Type:      tsNode.Type(),
		Value:     content,
		PosStart:  Position{Line: startLine, Column: int(startPoint.Column)},
		PosEnd:    Position{Line: int(endPoint.Row) + 1, Column: int(endPoint.Column)},
		Parent:    parent,
		Children:  []*ASTNode{},
		IsIgnored: isIgnored,
	}

	ctx.mu.Lock()
	ctx.NodeTable[node.ID] = node
	ctx.mu.Unlock()

	for i := 0; i < int(tsNode.NamedChildCount()); i++ {
		child := buildAST(tsNode.NamedChild(i), node, ctx, source, skipLines)
		if child != nil {
			node.Children = append(node.Children, child)
		}
	}
	return node
}

// generateNodeID creates a unique ID for an AST node
func generateNodeID(ctx *AnalysisContext) string {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return "node_" + fmt.Sprintf("%d", len(ctx.NodeTable))
}

// ReportVulnerabilities checks for vulnerabilities based on rules
func ReportVulnerabilities(ctx *AnalysisContext) {
	parsedIndex := make(map[string]*ASTNode)
	sourceLines := strings.Split(string(ctx.FileInfo.SourceCode), "\n")

	for _, node := range ctx.NodeTable {
		//log.Printf("[DEBUG] Processing node: Type=%s, Value=%q, Line=%d:%d", node.Type, node.Value, node.PosStart.Line, node.PosStart.Column)
		if node.IsIgnored {
			//log.Printf("[DEBUG] Node ignored due to okid comment: %q (Line %d)", node.Value, node.PosStart.Line)
			continue
		}
		key := node.Type + "|" + strings.TrimSpace(node.Value)
		parsedIndex[key] = node

		// Detect UserDefaults.standard.set
		if node.Type == "call_expression" && (strings.Contains(node.Value, "UserDefaults.standard.set") || hasChildWithValue(node, "UserDefaults.standard.set")) {
			log.Printf("[DEBUG] Found UserDefaults.standard.set candidate: %q (Line %d)", node.Value, node.PosStart.Line)
			for _, rule := range swiftrule.VulnerableSwiftNodes {
				if rule.ID == "swift-user-defaults" {
					hasSensitiveKey := false
					for _, child := range node.Children {
						log.Printf("[DEBUG] Checking child for sensitive key: Type=%s, Value=%q", child.Type, child.Value)
						if child.Type == "argument" && (strings.Contains(child.Value, "passphrase") ||
							strings.Contains(child.Value, "password") || strings.Contains(child.Value, "apiKey") ||
							strings.Contains(child.Value, "cryptoKey") || strings.Contains(child.Value, "clientSecret") ||
							strings.Contains(child.Value, "rsaPrivateKey") || strings.Contains(child.Value, "pass_phrase")) {
							hasSensitiveKey = true
							break
						}
					}
					if hasSensitiveKey && !isSuppressed("swift-user-defaults", node.PosStart.Line, sourceLines) {
						log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d\nDetails: %s\n\n",
							rule.ID, node.Type, node.Value, node.PosStart.Line, node.PosStart.Column, rule.Message)
					} else if hasSensitiveKey {
						log.Printf("[SWIFT SAFE] %s marked safe: %q (Line %d)", rule.ID, node.Value, node.PosStart.Line)
					}
				}
			}
		}

		// Detect SQLite injection
		if node.Type == "string_literal" && strings.Contains(node.Value, "SELECT") {
			log.Printf("[DEBUG] Found SQL string candidate: %q (Line %d)", node.Value, node.PosStart.Line)
			for _, rule := range swiftrule.VulnerableSwiftNodes {
				if rule.ID == "swift-potential-sqlite-injection" {
					if (strings.Contains(node.Value, "+") || strings.Contains(node.Value, "\\(") || strings.Contains(node.Value, "${")) &&
						!isSuppressed("swift-potential-sqlite-injection", node.PosStart.Line, sourceLines) {
						log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d\nDetails: %s\n\n",
							rule.ID, node.Type, node.Value, node.PosStart.Line, node.PosStart.Column, rule.Message)
					} else if strings.Contains(node.Value, "?") || isSuppressed("swift-potential-sqlite-injection", node.PosStart.Line, sourceLines) {
						log.Printf("[SWIFT SAFE] %s marked safe: %q (Line %d)", rule.ID, node.Value, node.PosStart.Line)
					}
				}
			}
		}

		// Detect WebView configuration
		if (node.Type == "assignment_expression" || node.Type == "call_expression") && strings.Contains(node.Value, "JavaScriptCanOpenWindowsAutomatically") {
			log.Printf("[DEBUG] Found JavaScriptCanOpenWindowsAutomatically candidate: %q (Line %d)", node.Value, node.PosStart.Line)
			for _, rule := range swiftrule.VulnerableSwiftNodes {
				if rule.ID == "swift-webview-config-allows-js-open-windows" {
					if strings.Contains(node.Value, "= true") && !isSuppressed("swift-webview-config-allows-js-open-windows", node.PosStart.Line, sourceLines) {
						log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d\nDetails: %s\n\n",
							rule.ID, node.Type, node.Value, node.PosStart.Line, node.PosStart.Column, rule.Message)
					} else if strings.Contains(node.Value, "= false") || isSuppressed("swift-webview-config-allows-js-open-windows", node.PosStart.Line, sourceLines) {
						log.Printf("[SWIFT SAFE] %s marked safe: %q (Line %d)", rule.ID, node.Value, node.PosStart.Line)
					}
				}
			}
		}
	}

	// Check static rules for insecure-random
	for _, rule := range swiftrule.VulnerableSwiftNodes {
		if rule.ID == "insecure-random" {
			for _, node := range ctx.NodeTable {
				if node.IsIgnored {
					continue
				}
				if node.Type == "call_expression" && (strings.Contains(node.Value, ".random(") ||
					strings.Contains(node.Value, "arc4random") || strings.Contains(node.Value, "SystemRandomNumberGenerator")) &&
					!isSuppressed("insecure-random", node.PosStart.Line, sourceLines) {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d\nDetails: %s\n\n",
						rule.ID, node.Type, node.Value, node.PosStart.Line, node.PosStart.Column, rule.Message)
				} else if node.Type == "call_expression" && strings.Contains(node.Value, ".random(") &&
					isSuppressed("insecure-random", node.PosStart.Line, sourceLines) {
					log.Printf("[SWIFT SAFE] %s marked safe: %q (Line %d)", rule.ID, node.Value, node.PosStart.Line)
				}
			}
		}
	}
}

// isSuppressed checks if a rule is suppressed by a // okid: comment
func isSuppressed(ruleID string, line int, sourceLines []string) bool {
	for offset := 0; offset <= 1 && line-1+offset < len(sourceLines); offset++ {
		if strings.Contains(sourceLines[line-1+offset], "// okid: "+ruleID) {
			log.Printf("[DEBUG] Found skip comment '// okid: %s' at line %d", ruleID, line+offset)
			return true
		}
	}
	return false
}

// hasChildWithValue checks if any child node contains the specified value
func hasChildWithValue(node *ASTNode, value string) bool {
	for _, child := range node.Children {
		if strings.Contains(child.Value, value) {
			return true
		}
		if hasChildWithValue(child, value) {
			return true
		}
	}
	return false
}
