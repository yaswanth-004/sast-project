package SASTTOOLPROJECT.Javaparser;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class Javaparser {
    
    public static void parseJavaSource(String filePath, String content) {
        try {
            // Process the Java file content here
            System.out.println("Processing Java file: " + filePath);
            
            // Example: Extract class names
            List<String> classNames = extractClassNames(content);
            
            // Example: Write analysis results to a report file
            writeAnalysisReport(filePath, classNames);
            
        } catch (Exception e) {
            System.err.println("Error processing Java file: " + filePath);
            e.printStackTrace();
        }
    }
    
    private static List<String> extractClassNames(String content) {
        List<String> classNames = new ArrayList<>();
        String[] lines = content.split("\\r?\\n");
        
        for (String line : lines) {
            line = line.trim();
            if (line.startsWith("class ") || line.contains(" class ")) {
                // Simple class name extraction (this is a basic example)
                String className = line.replaceAll(".*class\\s+([A-Za-z0-9_]+).*", "$1");
                if (!className.equals(line)) { // If pattern matched
                    classNames.add(className);
                }
            }
        }
        
        return classNames;
    }
    
    private static void writeAnalysisReport(String filePath, List<String> classNames) throws IOException {
        String reportPath = filePath + ".report.txt";
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(reportPath))) {
            writer.write("Java File Analysis Report\n");
            writer.write("File: " + filePath + "\n\n");
            writer.write("Classes found:\n");
            
            for (String className : classNames) {
                writer.write("- " + className + "\n");
            }
            
            writer.write("\nAnalysis completed successfully.\n");
        }
        
        System.out.println("Report generated: " + reportPath);
    }
    
    // Entry point for Go to call (via JNI or other integration)
    public static void ParseJavaSource(String filePath, String content) {
        parseJavaSource(filePath, content);
    }
}