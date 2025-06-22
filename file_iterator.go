package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	cstParser "sasttoolproject/CST_parasing"
	htmlParser "sasttoolproject/HTML_PARSER"
	cParser "sasttoolproject/c_c_pluse_parser"
	phpParser "sasttoolproject/php_parer"
	pythonParser "sasttoolproject/pythonparser_rule_engin"
	rustparser "sasttoolproject/rust_parser"
	swiftparser "sasttoolproject/swift_parser"

	"strings"
)

var supportedExtensions = map[string]bool{
	".py":    true,
	".c":     true,
	".cpp":   true,
	".cs":    true,
	".css":   true,
	".go":    true,
	".html":  true,
	".js":    true,
	".kt":    true,
	".php":   true,
	".rb":    true,
	".rs":    true,
	".swift": true,
	".ts":    true,
}

type SourceFile struct {
	Path    string
	Content string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	reportFile, err := os.Create("report.txt")
	if err != nil {
		log.Fatalf("Failed to create report.txt: %v", err)
	}
	defer reportFile.Close()

	multiWriter := io.MultiWriter(os.Stdout, reportFile)
	log.SetOutput(multiWriter)
	fmt.Fprintln(reportFile, "====== SAST Report ======")

	log.Println("Starting SAST file iterator")

	// ✅ Use flag to get --input instead of reading from terminal
	var root string
	flag.StringVar(&root, "input", "", "Root directory to scan")
	flag.Parse()

	if root == "" {
		log.Fatal("Missing --input argument. Usage: go run main.go --input ./testcode/")
	}

	// ✅ Validate directory
	if _, err := os.Stat(root); os.IsNotExist(err) {
		log.Fatalf("Directory %s does not exist", root)
	}

	// ✅ Same logic continues...
	var errors []error
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing %s: %v", path, err)
			return nil
		}
		if !d.IsDir() && isSupported(path) {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				log.Printf("Could not read file %s: %v", path, readErr)
				return nil
			}
			source := SourceFile{Path: path, Content: string(data)}
			log.Printf("Processing file: %s", source.Path)
			if procErr := processFile(source); procErr != nil {
				errors = append(errors, fmt.Errorf("file %s: %v", source.Path, procErr))
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Directory walk error: %v", err)
		errors = append(errors, fmt.Errorf("directory walk: %v", err))
	}

	if len(errors) > 0 {
		log.Println("Errors encountered during analysis:")
		for _, e := range errors {
			log.Println(e)
		}
		os.Exit(1)
	} else {
		log.Println("Analysis completed successfully")
	}
}
func isSupported(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return supportedExtensions[ext]
}
func processJavaFile(filePath, content string) error {
	// Call Java process: assumes class is compiled and present
	cmd := exec.Command(
		"java",
		"-cp", "C:/Users/HP/SASTTOOLPROJECT/javaparser",
		"SASTTOOLPROJECT.Javaparser.Javaparser", //
		filePath,
	)
	log.Println("[DEBUG] Calling Java parser for:", filePath)

	// Optionally, pass `content` via stdin (if JavaParser supports it)
	// If not used, remove lines below
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		defer stdin.Close()
		stdin.Write([]byte(content))
	}()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("java parser error: %v\nOutput: %s", err, string(output))
	}
	log.Printf("[JAVA PARSER OUTPUT] %s\n", string(output))
	return nil
}

func processFile(source SourceFile) error {
	switch {
	case strings.HasSuffix(source.Path, ".py"):
		pythonParser.ParsePythonSource(source.Path, source.Content)
		return nil
	case strings.HasSuffix(source.Path, ".c"):
		cParser.ParseCSource(source.Path, source.Content)
		return nil
	case strings.HasSuffix(source.Path, ".java"):
		return processJavaFile(source.Path, source.Content)

	case strings.HasSuffix(source.Path, ".rs"):
		// New: call Rust parser
		rustparser.ParseRustSource(source.Path, source.Content)
		return nil
	case strings.HasSuffix(source.Path, ".php"):
		phpParser.ParsePHPSource(source.Path, source.Content)
		return nil
	case strings.HasSuffix(source.Path, ".html"):
		htmlParser.ParseHTMLSource(source.Path, source.Content)
		return nil
	case strings.HasSuffix(source.Path, ".swift"):
		swiftparser.ParseSwiftSource(source.Path, source.Content)
		return nil
	default:
		cstParser.ParseSource(source.Path, source.Content)
		return nil
	}
}
