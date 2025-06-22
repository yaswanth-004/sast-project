package c_c_pluse_parser

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	crule "sasttoolproject/c_c_pluse_parser/crule"
	"strconv"
	"strings"
	"sync"

	ts "github.com/smacker/go-tree-sitter"
	c "github.com/smacker/go-tree-sitter/c"
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
func AnalyzeCCode(path string, code string) (*AnalysisContext, error) {
	ctx := &AnalysisContext{
		FileInfo:  &FileInfo{Path: path, FileName: filepath.Base(path)},
		NodeTable: make(map[string]*ASTNode),
	}
	rootNode, err := parseC(code, ctx)
	if err != nil {
		return nil, fmt.Errorf("c parsing failed: %w", err)
	}
	ctx.RootAST = rootNode
	return ctx, nil
}

func parseC(code string, ctx *AnalysisContext) (*ASTNode, error) {
	parser := ts.NewParser()
	parser.SetLanguage(c.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(code))
	if err != nil {
		return nil, fmt.Errorf("failed to parse C code: %v", err)
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

func ReportVulnerabilities(ctx *AnalysisContext) {
	parsedIndex := make(map[string]*ASTNode)
	freedVars := make(map[string]int)
	varAssigns := make(map[string]string)

	for _, node := range ctx.NodeTable {
		key := node.Type + "|" + node.Value
		parsedIndex[key] = node

		// === DEBUG PRINTS FOR AST ===
		if node.Type == "binary_expression" {
			log.Printf("[DEBUG] Parsed binary_expression node:\nType: %s\nValue: %q\n\n", node.Type, node.Value)
		} else if node.Type == "if_statement" {
			log.Printf("[DEBUG] Parsed if_statement node:\nType: %s\nValue: %q\nLocation: Line %d:%d → %d:%d\n\n",
				node.Type, node.Value,
				node.PosStart.Line, node.PosStart.Column,
				node.PosEnd.Line, node.PosEnd.Column)
		} else if node.Type == "call_expression" {
			log.Printf("[DEBUG] Parsed call_expression node:\nType: %s\nValue: %q\n\n", node.Type, node.Value)

			// Detect free()
			if strings.HasPrefix(node.Value, "free(") {
				varName := extractVarNameFromCall(node.Value)
				if varAssigns[varName] != "NULL" && varAssigns[varName] != "malloc" {
					freedVars[varName]++
					if freedVars[varName] > 1 {
						// Find the DoubleFree node to get its Message
						for _, vuln := range crule.VulnerableCNodes {
							if vuln.ID == "double-free" && vuln.Type == "call_expression" {
								log.Printf("[MATCH] ID: double-free\nType: call_expression\nValue: %q\nLocation: Line %d:%d → %d:%d\nDetails: %s\n\n",
									node.Value,
									node.PosStart.Line, node.PosStart.Column,
									node.PosEnd.Line, node.PosEnd.Column,
									vuln.Message)
								break
							}
						}
					} else {
						log.Printf("[DEBUG] free() on %q at Line %d:%d\n\n", varName, node.PosStart.Line, node.PosStart.Column)
					}
				}
			}

			// Track malloc assignment (var = malloc...)
			if strings.Contains(node.Value, "malloc(") && node.Parent != nil && node.Parent.Type == "assignment_expression" {
				var lhs string
				if len(node.Parent.Children) >= 1 {
					lhs = strings.TrimSpace(node.Parent.Children[0].Value)
				}
				if lhs != "" {
					varAssigns[lhs] = "malloc"
				}
			}
		} else if node.Type == "assignment_expression" {
			// Detect var = NULL
			if len(node.Children) == 2 {
				lhs := strings.TrimSpace(node.Children[0].Value)
				rhs := strings.TrimSpace(node.Children[1].Value)
				if rhs == "NULL" {
					varAssigns[lhs] = "NULL"
				}
			}
		} else if node.Type == "goto_statement" {
			log.Printf("[DEBUG] goto_statement:\n%q at Line %d:%d\n\n", node.Value, node.PosStart.Line, node.PosStart.Column)
		}
	}

	// === YAML or static rule-based matches ===
	for _, vuln := range crule.VulnerableCNodes {
		key := vuln.Type + "|" + vuln.Value
		if match, ok := parsedIndex[key]; ok {
			log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d → %d:%d\nDetails: %s\n\n",
				vuln.ID, vuln.Type, vuln.Value,
				match.PosStart.Line, match.PosStart.Column,
				match.PosEnd.Line, match.PosEnd.Column,
				vuln.Message)
		}
	}
}

// Helper to extract variable name from free(var)
func extractVarNameFromCall(call string) string {
	start := strings.Index(call, "(")
	end := strings.LastIndex(call, ")")
	if start == -1 || end == -1 || start >= end {
		return ""
	}
	return strings.TrimSpace(call[start+1 : end])
}

// ============== Entry Function (No Vulnerability Report) ==============
func ParseCSource(path string, code string) {
	ctx, err := AnalyzeCCode(path, code)
	if err != nil {
		log.Printf("C Analysis failed on %s: %v\n", path, err)
		return
	}
	log.Printf("C AST parsing complete for: %s\n", ctx.FileInfo.FileName)
	ReportVulnerabilities(ctx)
}
