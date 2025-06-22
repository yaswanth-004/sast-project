package CST_parasing

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	ts "github.com/smacker/go-tree-sitter"

	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/csharp"
	"github.com/smacker/go-tree-sitter/css"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/kotlin"
	"github.com/smacker/go-tree-sitter/ruby"
)

// ... [Unchanged code: ParseSource, printNode, Edge, FlowGraphs, flowGraphs, nodeMap, captureFlows]

func getLanguage(ext string) *ts.Language {
	switch ext {

	case ".cpp":
		return cpp.GetLanguage()
	case ".cs":
		return csharp.GetLanguage()
	case ".css":
		return css.GetLanguage()
	case ".go":
		return golang.GetLanguage()

	case ".js":
		return javascript.GetLanguage()
	case ".kt":
		return kotlin.GetLanguage()

	case ".rb":
		return ruby.GetLanguage()

	default:
		return nil
	}
}

// ParseSource parses the file content using the Tree-sitter grammar based on file extension
func ParseSource(path string, content string) {
	ext := strings.ToLower(filepath.Ext(path))

	lang := getLanguage(ext)
	if lang == nil {
		log.Printf("Unsupported file type: %s\n", ext)
		return
	}

	parser := ts.NewParser()
	parser.SetLanguage(lang)

	// Context-aware parsing
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(content))
	if err != nil {
		log.Printf("Error parsing file %s: %v\n", path, err)
		return
	}

	log.Printf("\n File: %s\n", path)
	//log.Println("CST Tree Structure:")
	printNode(tree.RootNode(), "")
	//  Generate Control and Data Flow Trees
	captureFlows(tree.RootNode())

	log.Println("\nControl Flow Tree Edges:")
	for _, edge := range flowGraphs.ControlFlow {
		log.Printf("   %s → %s (%s)\n", edge.FromID, edge.ToID, edge.Type)
	}

	fmt.Println("\n Data Flow Tree Edges:")
	for _, edge := range flowGraphs.DataFlow {
		log.Printf("   %s → %s (%s)\n", edge.FromID, edge.ToID, edge.Type)
	}

}

// getLanguage returns the correct Tree-sitter language based on file extension

// printNode recursively prints the CST tree structure
// printNode prints only named nodes to simulate an AST
func printNode(n *ts.Node, indent string) {
	if !n.IsNamed() {
		return
	}
	log.Printf("%s- %s [%d:%d - %d:%d]\n", indent, n.Type(), n.StartPoint().Row, n.StartPoint().Column, n.EndPoint().Row, n.EndPoint().Column)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		printNode(n.NamedChild(i), indent+"  ")
	}
}

// Edge represents a generic flow edge
type Edge struct {
	FromID string
	ToID   string
	Type   string
}

// FlowGraphs store edges for control and data flow
type FlowGraphs struct {
	ControlFlow []Edge
	DataFlow    []Edge
}

// flowGraphs will hold all edges generated
var flowGraphs = FlowGraphs{
	ControlFlow: []Edge{},
	DataFlow:    []Edge{},
}

// nodeMap links CST node identities to their content (ID → *ts.Node)
var nodeMap = map[string]*ts.Node{}

func captureFlows(n *ts.Node) {
	if n == nil || !n.IsNamed() {
		return
	}

	nodeID := fmt.Sprintf("%p", n)
	nodeMap[nodeID] = n

	if n.Type() == "if_statement" && n.NamedChildCount() >= 2 {
		thenBranch := n.NamedChild(1)
		flowGraphs.ControlFlow = append(flowGraphs.ControlFlow, Edge{
			FromID: nodeID,
			ToID:   fmt.Sprintf("%p", thenBranch),
			Type:   "if-true",
		})

		if n.NamedChildCount() >= 3 {
			elseBranch := n.NamedChild(2)
			flowGraphs.ControlFlow = append(flowGraphs.ControlFlow, Edge{
				FromID: nodeID,
				ToID:   fmt.Sprintf("%p", elseBranch),
				Type:   "if-false",
			})
		}
	}

	if n.Type() == "assignment_expression" && n.NamedChildCount() == 2 {
		left := n.NamedChild(0)
		right := n.NamedChild(1)
		if left.Type() == "identifier" && right.Type() == "identifier" {
			flowGraphs.DataFlow = append(flowGraphs.DataFlow, Edge{
				FromID: fmt.Sprintf("%p", right),
				ToID:   fmt.Sprintf("%p", left),
				Type:   "use-def",
			})
		}
	}

	// Recursive call only on named children
	for i := 0; i < int(n.NamedChildCount()); i++ {
		captureFlows(n.NamedChild(i))
	}
}
