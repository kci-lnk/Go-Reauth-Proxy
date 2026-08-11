package proxy

import (
	"os"
	"strings"
	"testing"
)

// Keep the HTTP handler from becoming less maintainable while its domain
// concerns are incrementally moved into focused proxy package files.
func TestHandlerSourceStaysWithinHotspotBudget(t *testing.T) {
	budgets := map[string]int{
		"handler.go":                7000,
		"html_response_mutation.go": 700,
		"http_auth.go":              1000,
	}
	for file, maxLines := range budgets {
		t.Run(file, func(t *testing.T) {
			contents, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read source: %v", err)
			}
			lineCount := strings.Count(string(contents), "\n")
			if len(contents) > 0 && contents[len(contents)-1] != '\n' {
				lineCount++
			}
			if lineCount > maxLines {
				t.Fatalf(
					"%s has %d lines, exceeding the %d-line hotspot budget; split a cohesive concern before adding more behavior",
					file,
					lineCount,
					maxLines,
				)
			}
		})
	}
}
