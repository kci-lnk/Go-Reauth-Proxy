package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseBenchmarkSamplesUsesMedianAndStripsCPUCount(t *testing.T) {
	parsed, err := parseBenchmarkSamples(strings.NewReader(`
BenchmarkHandlerEndToEnd/Path/AuthOff-10  100  100 ns/op  64 B/op  2 allocs/op
BenchmarkHandlerEndToEnd/Path/AuthOff-10  100  300 ns/op  128 B/op  4 allocs/op
BenchmarkHandlerEndToEnd/Path/AuthOff-10  100  200 ns/op  96 B/op  3 allocs/op
BenchmarkIncomplete-10 100 25 ns/op
`))
	if err != nil {
		t.Fatalf("parse benchmark samples: %v", err)
	}
	got, ok := parsed["BenchmarkHandlerEndToEnd/Path/AuthOff"]
	if !ok {
		t.Fatalf("missing normalized benchmark name: %#v", parsed)
	}
	if got != (benchmarkSummary{Nanoseconds: 200, Bytes: 96, Allocs: 3}) {
		t.Fatalf("summary = %#v", got)
	}
}

func TestCompareBenchmarksRejectsMetricRegressionAndMissingCoverage(t *testing.T) {
	base := map[string]benchmarkSummary{
		"BenchmarkHot":  {Nanoseconds: 100, Bytes: 20, Allocs: 2},
		"BenchmarkGone": {Nanoseconds: 50, Bytes: 5, Allocs: 1},
	}
	current := map[string]benchmarkSummary{
		"BenchmarkHot": {Nanoseconds: 130, Bytes: 22, Allocs: 3},
	}
	var output bytes.Buffer
	err := compareBenchmarks(base, current, tolerances{Latency: 0.20, Bytes: 0.05, Allocs: 0.05}, &output)
	if err == nil {
		t.Fatal("expected regression failure")
	}
	for _, expected := range []string{
		"BenchmarkHot ns/op regressed",
		"BenchmarkHot B/op regressed",
		"BenchmarkHot allocs/op regressed",
		"BenchmarkGone is missing",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("error %q missing %q", err, expected)
		}
	}
	if !strings.Contains(output.String(), "BenchmarkHot: ns/op 100 -> 130") {
		t.Fatalf("missing benchmark report: %s", output.String())
	}
}

func TestCompareBenchmarksAllowsValuesWithinTolerance(t *testing.T) {
	base := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 20, Allocs: 2}}
	current := map[string]benchmarkSummary{
		"BenchmarkHot": {Nanoseconds: 120, Bytes: 21, Allocs: 2},
		"BenchmarkNew": {Nanoseconds: 10, Bytes: 1, Allocs: 1},
	}
	if err := compareBenchmarks(base, current, tolerances{Latency: 0.20, Bytes: 0.05, Allocs: 0.05}, &bytes.Buffer{}); err != nil {
		t.Fatalf("compare benchmarks: %v", err)
	}
}

func TestCompareBenchmarksAllowsOneReportedAllocationOfRoundingSlack(t *testing.T) {
	base := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 40, Allocs: 1}}
	current := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 40, Allocs: 2}}
	limits := tolerances{Latency: 0.20, Bytes: 0.05, Allocs: 0.05, AllocsAbsolute: 1}
	if err := compareBenchmarks(base, current, limits, &bytes.Buffer{}); err != nil {
		t.Fatalf("compare benchmarks: %v", err)
	}
}

func TestCompareBenchmarksRejectsAllocationsBeyondAbsoluteAndRelativeSlack(t *testing.T) {
	base := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 40, Allocs: 1}}
	current := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 40, Allocs: 3}}
	limits := tolerances{Latency: 0.20, Bytes: 0.05, Allocs: 0.05, AllocsAbsolute: 1}
	err := compareBenchmarks(base, current, limits, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "allocs/op regressed") {
		t.Fatalf("unexpected allocs result: %v", err)
	}
}

func TestCompareBenchmarksRejectsNonZeroMetricAfterZeroBaseline(t *testing.T) {
	err := compareBenchmarks(
		map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 0, Bytes: 0, Allocs: 0}},
		map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 1, Bytes: 0, Allocs: 0}},
		tolerances{Latency: 0.20, Bytes: 0.05, Allocs: 0.05},
		&bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "increased from zero") {
		t.Fatalf("unexpected zero-baseline result: %v", err)
	}
}
