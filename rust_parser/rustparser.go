package rustparser

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	rustrules "sasttoolproject/rust_parser/rust_rules"
	"strconv"
	"strings"
	"sync"

	ts "github.com/smacker/go-tree-sitter"
	rust "github.com/smacker/go-tree-sitter/rust"
)

// ============== Node Structures ==============
type Position struct {
	Line   int
	Column int
}

type ASTNode struct {
	ID       string
	Type     string
	Value    string
	PosStart Position
	PosEnd   Position
	Children []*ASTNode
	Parent   *ASTNode
}

type AnalysisContext struct {
	RootAST   *ASTNode
	FileInfo  *FileInfo
	NodeTable map[string]*ASTNode
	mu        sync.Mutex
}

type FileInfo struct {
	Path     string
	FileName string
}

// ============== Main Analyzer ==============
func AnalyzeRustCode(path string, code string) (*AnalysisContext, error) {
	ctx := &AnalysisContext{
		FileInfo:  &FileInfo{Path: path, FileName: filepath.Base(path)},
		NodeTable: make(map[string]*ASTNode),
	}
	rootNode, err := parseRust(code, ctx)
	if err != nil {
		return nil, fmt.Errorf("Rust parsing failed: %v", err)
	}
	ctx.RootAST = rootNode
	return ctx, nil
}

func parseRust(code string, ctx *AnalysisContext) (*ASTNode, error) {
	parser := ts.NewParser()
	parser.SetLanguage(rust.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(code))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Rust code: %v", err)
	}
	return buildAST(tree.RootNode(), nil, ctx, []byte(code)), nil
}

func buildAST(tsNode *ts.Node, parent *ASTNode, ctx *AnalysisContext, source []byte) *ASTNode {
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
	node := &ASTNode{
		ID:    generateNodeID(ctx),
		Type:  tsNode.Type(),
		Value: content,
		PosStart: Position{
			Line:   int(startPoint.Row) + 1,
			Column: int(startPoint.Column),
		},
		PosEnd: Position{
			Line:   int(endPoint.Row) + 1,
			Column: int(endPoint.Column),
		},
		Parent:   parent,
		Children: []*ASTNode{},
	}
	ctx.mu.Lock()
	ctx.NodeTable[node.ID] = node
	ctx.mu.Unlock()

	for i := 0; i < int(tsNode.NamedChildCount()); i++ {
		child := buildAST(tsNode.NamedChild(i), node, ctx, source)
		if child != nil {
			node.Children = append(node.Children, child)
		}
	}
	return node
}

func generateNodeID(ctx *AnalysisContext) string {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return "node_" + strconv.Itoa(len(ctx.NodeTable))
}

// ReportVulnerabilities scans AST and matches against vulnerability rules.
func ReportVulnerabilities(ctx *AnalysisContext) {
	parsedIndex := make(map[string]*ASTNode)

	// Index all nodes by "Type|Value"
	for _, node := range ctx.NodeTable {
		key := node.Type + "|" + node.Value
		parsedIndex[key] = node

		// Optional: debug log
		if node.Type == "unsafe_block" || node.Type == "call_expression" {
			log.Printf("[DEBUG] Type: %s\nValue: %q\nLocation: Line %d:%d → Line %d:%d\n",
				node.Type, node.Value,
				node.PosStart.Line, node.PosStart.Column,
				node.PosEnd.Line, node.PosEnd.Column)
		}
	}

	// Modular rule matching
	for _, node := range ctx.NodeTable {

		// Rule: env::args_os() (matched inside a call_expression node)
		if node.Type == "call_expression" && strings.Contains(node.Value, "env::args_os") {
			printRustVulnerability(node, rustrules.ArgsOsUsage)
		}

		// Rule: unsafe block
		if node.Type == "unsafe_block" {
			printRustVulnerability(node, rustrules.UnsafeBlockUsage)
		}

		// Rule: unwrap()
		if node.Type == "call_expression" && strings.Contains(node.Value, "unwrap") {
			printRustVulnerability(node, rustrules.UnwrapUsage)
		}
		if node.Type == "call_expression" && strings.Contains(node.Value, "env::args()") {
			printRustSafety(node, rustrules.ArgsUsageSafe)
		}
		if node.Type == "call_expression" && strings.Contains(node.Value, "env::current_exe") {
			printRustVulnerability(node, rustrules.CurrentExeUsage)
		}
		if node.Type == "call_expression" && strings.Contains(node.Value, "Md2::new") {
			printRustVulnerability(node, rustrules.InsecureHashMd2)
		}

		if node.Type == "call_expression" && strings.Contains(node.Value, "Md4::new") {
			printRustVulnerability(node, rustrules.InsecureHashMd4)
		}

		if node.Type == "call_expression" && strings.Contains(node.Value, "Md5::new") {
			printRustVulnerability(node, rustrules.InsecureHashMd5)
		}

		if node.Type == "call_expression" && strings.Contains(node.Value, "Sha1::new") {
			printRustVulnerability(node, rustrules.InsecureHashSha1)
		}

		if node.Type == "call_expression" && strings.Contains(node.Value, "Sha256::new") {
			printRustSafety(node, rustrules.SecureHashSha256)
		}
		if node.Type == "call_expression" && strings.Contains(node.Value, "danger_accept_invalid_hostnames") {
			printRustVulnerability(node, rustrules.ReqwestInvalidHostnames)
		}

		if node.Type == "call_expression" && strings.Contains(node.Value, "danger_accept_invalid_certs") {
			printRustVulnerability(node, rustrules.ReqwestInvalidCerts)
		}

		if node.Type == "call_expression" && strings.Contains(node.Value, "reqwest::Client::builder") &&
			!strings.Contains(node.Value, "danger_accept_invalid") {
			printRustSafety(node, rustrules.ReqwestSafeUsage)
		}
		if node.Type == "call_expression" && strings.Contains(node.Value, "headers.insert") &&
			(strings.Contains(node.Value, "AUTHORIZATION") || strings.Contains(node.Value, "Authorization")) &&
			!strings.Contains(node.Value, "set_sensitive(true)") {
			printRustVulnerability(node, rustrules.ReqwestSetSensitive)
		}
		if node.Type == "call_expression" &&
			strings.Contains(node.Value, "set_certificate_verifier") &&
			strings.Contains(node.Value, "dangerous") {
			printRustVulnerability(node, rustrules.RustlsDangerousVerifier)
		}

	}
}

// Helper function to print matched vulnerability details
func printRustVulnerability(node *ASTNode, rule rustrules.RustRule) {
	fmt.Println(" Vulnerability Found!")
	fmt.Printf("Code         : %q\n", node.Value)
	fmt.Printf("Location     : Line %d:%d → Line %d:%d\n",
		node.PosStart.Line, node.PosStart.Column,
		node.PosEnd.Line, node.PosEnd.Column)
	fmt.Printf("Message      : %s\n", rule.Message)
	fmt.Printf("Recommendation: %s\n", rule.Recommendation)
	fmt.Printf("CWE          : %s\n", rule.CWE)
	fmt.Printf("Severity     : %s\n", rule.Severity)
	fmt.Println("---------------------------------------------------")
}
func printRustSafety(node *ASTNode, rule rustrules.RustRule) {
	fmt.Println(" Safe Usage Detected")
	fmt.Printf("Code         : %q\n", node.Value)
	fmt.Printf("Location     : Line %d:%d → Line %d:%d\n",
		node.PosStart.Line, node.PosStart.Column,
		node.PosEnd.Line, node.PosEnd.Column)
	fmt.Printf("Message      : %s\n", rule.Message)
	fmt.Println("---------------------------------------------------")
}

// ============== Entry Function (Without Vulnerability Report) ==============
func ParseRustSource(path string, code string) {
	ctx, err := AnalyzeRustCode(path, code)
	if err != nil {
		log.Printf("Rust analysis failed on %s: %v\n", path, err)
		return
	}
	log.Printf("Rust AST parsing complete for: %s\n", ctx.FileInfo.FileName)

	// Optional: Print top-level nodes for verification
	for _, node := range ctx.NodeTable {
		if node.Parent == nil {
			log.Printf("[TOP-LEVEL NODE] %s: %q at Line %d:%d → Line %d:%d\n",
				node.Type, node.Value, node.PosStart.Line, node.PosStart.Column, node.PosEnd.Line, node.PosEnd.Column)
		}
	}
	ReportVulnerabilities(ctx)
}
