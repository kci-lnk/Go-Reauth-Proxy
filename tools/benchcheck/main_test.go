package main

import (
	"bytes"
	"reflect"
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
	if !reflect.DeepEqual(got, benchmarkSummary{Nanoseconds: 200, Bytes: 96, Allocs: 3, latencySamples: []float64{100, 200, 300}}) {
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

func TestCompareBenchmarksByteRoundingAllowanceStillRejectsRealGrowth(t *testing.T) {
	base := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 0, Allocs: 0}}
	limits := tolerances{Latency: 0.10, Bytes: 0.05, BytesAbsolute: 1}
	for _, amount := range []float64{0.5, 1, 2} {
		current := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: amount, Allocs: 0}}
		err := compareBenchmarks(base, current, limits, &bytes.Buffer{})
		if (err != nil) != (amount > 1) {
			t.Fatalf("bytes=%v: %v", amount, err)
		}
	}
}

func TestCompareBenchmarksTenPercentLatencyLimit(t *testing.T) {
	base := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100}}
	for _, latency := range []float64{106, 110, 111} {
		current := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: latency}}
		err := compareBenchmarks(base, current, tolerances{Latency: 0.10}, &bytes.Buffer{})
		if (err != nil) != (latency > 110) {
			t.Fatalf("latency=%v: %v", latency, err)
		}
	}
}

func TestCompareBenchmarksFifteenPercentByteLimit(t *testing.T) {
	base := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: 100}}
	for _, amount := range []float64{110, 114, 116} {
		current := map[string]benchmarkSummary{"BenchmarkHot": {Nanoseconds: 100, Bytes: amount}}
		err := compareBenchmarks(base, current, tolerances{Bytes: 0.15, BytesAbsolute: 1}, &bytes.Buffer{})
		if (err != nil) != (amount > 115) {
			t.Fatalf("bytes=%v: %v", amount, err)
		}
	}
}

func TestLatencyConfidenceRetainsStableRegressionsAndHandlesNoise(t *testing.T) {
	for _, tc := range []struct {
		name          string
		base, current []float64
		reject        bool
	}{
		{"stable regression", []float64{99, 100, 100, 100, 100, 101}, []float64{129, 130, 130, 130, 130, 131}, true},
		{"noisy overlap", []float64{34, 38, 48, 50, 50, 70}, []float64{50, 54, 59, 63, 85, 960}, false},
		{"insufficient samples", []float64{100, 100}, []float64{130, 130}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := benchmarkSummary{Nanoseconds: median(append([]float64(nil), tc.base...)), latencySamples: tc.base}
			c := benchmarkSummary{Nanoseconds: median(append([]float64(nil), tc.current...)), latencySamples: tc.current}
			result := latencyRegression(tc.name, b, c, 0.10, &bytes.Buffer{})
			if (result != "") != tc.reject {
				t.Fatalf("unexpected latency result: %q", result)
			}
		})
	}
}
