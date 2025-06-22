package pythonparser_rule_engin

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	baseh_operation "sasttoolproject/pythonparser_rule_engin/YAML_Rules"
	"strconv"
	"strings"
	"sync"

	ts "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

// ================== Node Structures ==================
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

func AnalyzePythonCode(path string, code string) (*AnalysisContext, error) {
	ctx := &AnalysisContext{
		FileInfo:  &FileInfo{Path: path, FileName: filepath.Base(path)},
		NodeTable: make(map[string]*ASTNode),
	}
	rootNode, err := parsePython(code, ctx)
	if err != nil {
		return nil, fmt.Errorf("parsing phase failed: %v", err)
	}
	ctx.RootAST = rootNode
	return ctx, nil
}

func parsePython(code string, ctx *AnalysisContext) (*ASTNode, error) {
	parser := ts.NewParser()
	parser.SetLanguage(python.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(code))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Python code: %v", err)
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
			Line:   int(startPoint.Row) + 1, // 1-based indexing
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
func ReportVulnerables(ctx *AnalysisContext) {
	parsedIndex := make(map[string]*ASTNode)
	// Build index and debug log for all AST nodes
	for _, node := range ctx.NodeTable {
		key := node.Type + "|" + node.Value
		parsedIndex[key] = node

		switch node.Type {
		case "call":
			log.Printf("[DEBUG] Parsed call node:\nType: %s\nValue: %q\n\n", node.Type, node.Value)
		case "pair", "dictionary":
			log.Printf("[DEBUG] Parsed node:\nType: %s\nValue: %q\n\n", node.Type, node.Value)
		case "if_statement":
			log.Printf("[DEBUG] Parsed if_statement node:\nType: %s\nValue: %q\nLocation: Line %d:%d → %d:%d\n\n",
				node.Type, node.Value,
				node.PosStart.Line, node.PosStart.Column,
				node.PosEnd.Line, node.PosEnd.Column)
		}
	}

	// Rule match via exact YAML rules (semantic rules)
	for _, vuln := range baseh_operation.VulnerableBashNodes {
		key := vuln.Type + "|" + vuln.Value
		if match, ok := parsedIndex[key]; ok {
			log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d → Line %d:%d\nDetails: %s\n\n",
				vuln.ID, vuln.Type, vuln.Value,
				match.PosStart.Line, match.PosStart.Column,
				match.PosEnd.Line, match.PosEnd.Column,
				vuln.Message)
		}
	}

	// Custom Rule 1: Detect socket shutdown followed by close in try blocks
	for _, node := range ctx.NodeTable {
		if node.Type == "try_statement" {
			var shutdownFound, closeFound bool
			for _, child := range node.Children {
				if child.Type == "expression_statement" {
					if strings.Contains(child.Value, "shutdown") {
						shutdownFound = true
					}
					if strings.Contains(child.Value, "close") {
						closeFound = true
					}
				}
			}
			if shutdownFound && closeFound {
				// Find the matching ASTNode from VulnerableBashNodes to get the Message
				for _, vuln := range baseh_operation.VulnerableBashNodes {
					if vuln.ID == "socket_shutdown_close_vuln" && vuln.Type == "try_statement" {
						log.Printf("[MATCH] ID: socket_shutdown_close_vuln\nType: try_statement\nValue: composite call\nLocation: Line %d:%d → Line %d:%d\nDetails: %s\n\n",
							node.PosStart.Line, node.PosStart.Column,
							node.PosEnd.Line, node.PosEnd.Column,
							vuln.Message)
						break
					}
				}
			}
		}
	}

	// Custom Rule 2: Detect insecure Cipher usage (no mode or mode=None)
	for _, node := range ctx.NodeTable {
		if node.Type == "call" && strings.HasPrefix(node.Value, "Cipher(") {
			if strings.Contains(node.Value, "mode=None") || !strings.Contains(node.Value, "mode=") {
				// Find the matching ASTNode from VulnerableBashNodes
				for _, vuln := range baseh_operation.VulnerableBashNodes {
					if vuln.ID == "insecure_cipher_algorithm_arc4" || vuln.ID == "insecure_cipher_mode_none" {
						log.Printf("[MATCH] ID: insecure_cipher_algorithm_usage\nType: call\nValue: %q\nLocation: Line %d:%d → %d:%d\nDetails: %s\n\n",
							node.Value,
							node.PosStart.Line, node.PosStart.Column,
							node.PosEnd.Line, node.PosEnd.Column,
							vuln.Message)
						break
					}
				}
			}
		}
	}

	// Custom Rule 3: Detect insecure mode ECB
	for _, node := range ctx.NodeTable {
		if node.Type == "call" && (strings.Contains(node.Value, "modes.ECB(") || strings.Contains(node.Value, "ECB(")) {
			for _, vuln := range baseh_operation.VulnerableBashNodes {
				if vuln.ID == "insecure_cipher_mode_ecb" {
					log.Printf("[MATCH] ID: insecure_cipher_mode_ecb\nType: call\nValue: %q\nLocation: Line %d:%d → %d:%d\nDetails: %s\n\n",
						node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						vuln.Message)
					break
				}
			}
		}
	}

	// Custom Rule 4: Detect insecure hash algorithm MD5
	for _, node := range ctx.NodeTable {
		if node.Type == "call" && strings.Contains(node.Value, "MD5(") {
			for _, vuln := range baseh_operation.VulnerableBashNodes {
				if vuln.ID == "insecure_hash_algorithm_md5" {
					log.Printf("[MATCH] ID: insecure_hash_algorithm_md5\nType: call\nValue: %q\nLocation: Line %d:%d → %d:%d\nDetails: %s\n\n",
						node.Value,
						node.PosStart.Line, node.PosStart.Column,
						node.PosEnd.Line, node.PosEnd.Column,
						vuln.Message)
					break
				}
			}
		}
	}
}

func ParsePythonSource(path string, code string) {
	ctx, err := AnalyzePythonCode(path, code)
	if err != nil {
		log.Printf("Analysis failed on %s: %v\n", path, err)
		return
	}

	ReportVulnerables(ctx)
}
