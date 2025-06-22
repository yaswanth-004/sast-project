package htmlparser

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	htmlrule "sasttoolproject/HTML_PARSER/htmlrules" // Corrected import path

	ts "github.com/smacker/go-tree-sitter"
	html "github.com/smacker/go-tree-sitter/html"
	js "github.com/smacker/go-tree-sitter/javascript"
)

type Position struct {
	Line   int
	Column int
}

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

func ParseHTMLSource(path string, code string) {
	ctx, err := AnalyzeHTML(path, code)
	if err != nil {
		log.Printf("HTML analysis failed for %s: %v", path, err)
		return
	}
	log.Printf("HTML AST parsing complete for: %s", ctx.FileInfo.FileName)
	ReportVulnerabilities(ctx)

	seenJS := make(map[string]bool) // Avoid duplicate analysis
	for _, node := range ctx.NodeTable {
		if node.Type == "script_element" || node.Type == "raw_text" {
			jsCode := strings.TrimSpace(node.Value)
			if jsCode == "" || seenJS[jsCode] {
				continue
			}
			seenJS[jsCode] = true
			analyzeJavaScript(jsCode, node.PosStart.Line)
		}
	}
}

func analyzeJavaScript(jsCode string, baseLine int) {
	parser := ts.NewParser()
	parser.SetLanguage(js.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, []byte(jsCode))
	if err != nil {
		log.Printf("[JS ERROR] Failed to parse JS: %v", err)
		return
	}

	scanJSForVulnerabilities(tree.RootNode(), jsCode, baseLine)
}

func scanJSForVulnerabilities(node *ts.Node, source string, baseLine int) {
	if node == nil {
		return
	}

	sourceLines := strings.Split(source, "\n")
	line := int(node.StartPoint().Row) + baseLine // Adjust line number relative to HTML

	// Check for eval
	if node.Type() == "call_expression" {
		callee := node.ChildByFieldName("function")
		if callee != nil && callee.Type() == "identifier" && callee.Content([]byte(source)) == "eval" {
			content := node.Content([]byte(source))
			isSafe := false
			for offset := 0; offset <= 1 && line-1+offset < len(sourceLines); offset++ {
				if strings.Contains(sourceLines[line-baseLine+offset], "// ok: eval-detected") {
					isSafe = true
					break
				}
			}
			if isSafe {
				log.Printf("[JS SAFE] eval usage marked safe: %q (Line %d)", content, line)
			} else {
				log.Printf("[JS VULN] Dynamic eval detected: %q (Line %d)", content, line)
			}
		}
	}

	// Check for innerHTML/outerHTML
	if node.Type() == "assignment_expression" {
		left := node.ChildByFieldName("left")
		if left != nil && left.Type() == "member_expression" {
			property := left.ChildByFieldName("property")
			if property != nil && (property.Content([]byte(source)) == "innerHTML" || property.Content([]byte(source)) == "outerHTML") {
				content := node.Content([]byte(source))
				isSafe := false
				for offset := 0; offset <= 1 && line-1+offset < len(sourceLines); offset++ {
					if strings.Contains(sourceLines[line-baseLine+offset], "// ok: insecure-document-method") {
						isSafe = true
						break
					}
				}
				if isSafe {
					log.Printf("[JS SAFE] %s usage marked safe: %q (Line %d)", property.Content([]byte(source)), content, line)
				} else {
					log.Printf("[JS VULN] Insecure %s detected: %q (Line %d)", property.Content([]byte(source)), content, line)
				}
			}
		}
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		scanJSForVulnerabilities(node.Child(i), source, baseLine)
	}
}

func AnalyzeHTML(path string, code string) (*AnalysisContext, error) {
	ctx := &AnalysisContext{
		FileInfo:  &FileInfo{Path: path, FileName: filepath.Base(path)},
		NodeTable: make(map[string]*ASTNode),
	}
	rootNode, err := parseHTML(code, ctx)
	if err != nil {
		return nil, fmt.Errorf("html parsing failed: %w", err)
	}
	ctx.RootAST = rootNode
	return ctx, nil
}

func parseHTML(code string, ctx *AnalysisContext) (*ASTNode, error) {
	parser := ts.NewParser()
	parser.SetLanguage(html.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(code))
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %v", err)
	}
	skipLines := extractAllSkipLines(code) // Use multi-rule skip lines
	return buildAST(tree.RootNode(), nil, ctx, []byte(code), skipLines), nil
}

func extractAllSkipLines(source string) map[int][]string {
	lines := strings.Split(source, "\n")
	skipMap := make(map[int][]string)
	for i, line := range lines {
		if strings.Contains(line, "// ok:") {
			parts := strings.Split(line, "// ok:")
			if len(parts) > 1 {
				ruleIDs := strings.Fields(parts[1])
				skipMap[i+1] = ruleIDs // 1-based line numbers
			}
		}
	}
	return skipMap
}

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

	// Check if node should be ignored based on skipLines
	isIgnored := false
	if ruleIDs, ok := skipLines[startLine]; ok {
		for _, ruleID := range ruleIDs {
			if ruleID == "eval-detected" || ruleID == "insecure-document-method" || ruleID == "missing-integrity" {
				isIgnored = true
				break
			}
		}
	}

	node := &ASTNode{
		ID:    generateNodeID(ctx),
		Type:  tsNode.Type(),
		Value: content,
		PosStart: Position{
			Line:   startLine,
			Column: int(startPoint.Column),
		},
		PosEnd: Position{
			Line:   int(endPoint.Row) + 1,
			Column: int(endPoint.Column),
		},
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

func generateNodeID(ctx *AnalysisContext) string {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return "node_" + strconv.Itoa(len(ctx.NodeTable))
}

func ReportVulnerabilities(ctx *AnalysisContext) {
	parsedIndex := make(map[string]*ASTNode)
	for _, node := range ctx.NodeTable {
		if node.IsIgnored {
			continue
		}
		key := node.Type + "|" + strings.TrimSpace(node.Value)
		parsedIndex[key] = node
	}

	// Check for HTML vulnerabilities
	for _, rule := range htmlrule.VulnerableHTMLNodes {
		key := rule.Type + "|" + strings.TrimSpace(rule.Value)
		if match, ok := parsedIndex[key]; ok {
			log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d → %d:%d\nDetails: %s\n\n",
				rule.ID, rule.Type, match.Value,
				match.PosStart.Line, match.PosStart.Column,
				match.PosEnd.Line, match.PosEnd.Column,
				rule.Message)
		}
	}

	// Check for missing integrity attributes
	for _, node := range ctx.NodeTable {
		if node.Type == "element" && (node.Value == "<script>" || node.Value == "<link>") {
			hasIntegrity := false
			hasExternalSrc := false
			isLink := node.Value == "<link>"
			isStylesheet := false
			hrefOrSrc := ""

			for _, child := range node.Children {
				if child.Type == "attribute" {
					if child.Value == "integrity" {
						hasIntegrity = true
					}
					if (child.Value == "src" && !isLink) || (child.Value == "href" && isLink) {
						for _, attrChild := range child.Children {
							if attrChild.Type == "attribute_value" {
								hrefOrSrc = strings.Trim(attrChild.Value, "\"'")
								if strings.HasPrefix(hrefOrSrc, "https://") || strings.HasPrefix(hrefOrSrc, "//") {
									hasExternalSrc = true
								}
							}
						}
					}
					if isLink && child.Value == "rel" {
						for _, attrChild := range child.Children {
							if attrChild.Type == "attribute_value" && strings.Contains(attrChild.Value, "stylesheet") {
								isStylesheet = true
							}
						}
					}
				}
			}

			// Skip exceptions
			if hasExternalSrc {
				if strings.HasPrefix(hrefOrSrc, "https://www.google-analytics.com") ||
					strings.HasPrefix(hrefOrSrc, "https://www.googletagmanager.com") ||
					strings.HasPrefix(hrefOrSrc, "https://fonts.googleapis.com") ||
					strings.HasPrefix(hrefOrSrc, "https://fonts.gstatic.com") {
					continue
				}
			}

			if hasExternalSrc && !hasIntegrity && (!isLink || isStylesheet) {
				ruleID := "missing-integrity"
				isIgnored := false
				if ruleIDs, ok := extractAllSkipLines(ctx.RootAST.Value)[node.PosStart.Line]; ok {
					for _, rule := range ruleIDs {
						if rule == ruleID {
							isIgnored = true
							break
						}
					}
				}
				if !isIgnored {
					log.Printf("[MATCH] ID: %s\nType: %s\nValue: %q\nLocation: Line %d:%d\nDetails: %s\n\n",
						ruleID, node.Type, hrefOrSrc, node.PosStart.Line, node.PosStart.Column,
						fmt.Sprintf("Missing integrity attribute on external %s. CWE-829; Recommendation: Add 'integrity' and 'crossorigin'.", node.Value))
				}
			}
		}
	}
}
