// Command benchcheck compares repeatable Go benchmark samples without an
// external benchstat dependency. It is intentionally small so the CI gate
// runs with only the pinned Go toolchain available in this repository.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
)

type benchmarkSample struct {
	Nanoseconds float64
	Bytes       float64
	Allocs      float64
}

type benchmarkSummary struct {
	Nanoseconds    float64
	Bytes          float64
	Allocs         float64
	latencySamples []float64
}

type tolerances struct {
	Latency        float64
	Bytes          float64
	BytesAbsolute  float64
	Allocs         float64
	AllocsAbsolute float64
}

func main() {
	basePath := flag.String("base", "", "benchmark output for the PR base revision")
	currentPath := flag.String("current", "", "benchmark output for the current revision")
	latencyTolerance := flag.Float64("max-latency-regression", 0.10, "maximum allowed ns/op regression as a fraction")
	bytesTolerance := flag.Float64("max-bytes-regression", 0.15, "maximum allowed B/op regression as a fraction")
	bytesAbsoluteTolerance := flag.Float64("max-bytes-absolute-regression", 1, "maximum allowed B/op regression in reported byte units")
	allocsTolerance := flag.Float64("max-allocs-regression", 0.05, "maximum allowed allocs/op regression as a fraction")
	allocsAbsoluteTolerance := flag.Float64("max-allocs-absolute-regression", 1, "maximum allowed allocs/op regression in reported allocation units")
	flag.Parse()

	if *basePath == "" || *currentPath == "" {
		fatal(errors.New("--base and --current are required"))
	}
	limits := tolerances{
		Latency:        *latencyTolerance,
		Bytes:          *bytesTolerance,
		BytesAbsolute:  *bytesAbsoluteTolerance,
		Allocs:         *allocsTolerance,
		AllocsAbsolute: *allocsAbsoluteTolerance,
	}
	if err := validateTolerances(limits); err != nil {
		fatal(err)
	}

	base, err := readBenchmarkFile(*basePath)
	if err != nil {
		fatal(fmt.Errorf("read base benchmark output: %w", err))
	}
	current, err := readBenchmarkFile(*currentPath)
	if err != nil {
		fatal(fmt.Errorf("read current benchmark output: %w", err))
	}
	if err := compareBenchmarks(base, current, limits, os.Stdout); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "benchcheck: %v\n", err)
	os.Exit(1)
}

func validateTolerances(limits tolerances) error {
	for label, value := range map[string]float64{
		"latency":         limits.Latency,
		"bytes":           limits.Bytes,
		"bytes-absolute":  limits.BytesAbsolute,
		"allocs":          limits.Allocs,
		"allocs-absolute": limits.AllocsAbsolute,
	} {
		if value < 0 || value > 10 {
			return fmt.Errorf("%s tolerance must be between 0 and 10", label)
		}
	}
	return nil
}

func readBenchmarkFile(path string) (map[string]benchmarkSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return parseBenchmarkSamples(file)
}

func parseBenchmarkSamples(input io.Reader) (map[string]benchmarkSummary, error) {
	samples := make(map[string][]benchmarkSample)
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[0], "Benchmark") {
			continue
		}
		name := benchmarkName(fields[0])
		sample, ok := parseBenchmarkLine(fields)
		if !ok {
			continue
		}
		samples[name] = append(samples[name], sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(samples) == 0 {
		return nil, errors.New("no complete benchmark samples found")
	}

	summaries := make(map[string]benchmarkSummary, len(samples))
	for name, values := range samples {
		nanoseconds := make([]float64, 0, len(values))
		bytes := make([]float64, 0, len(values))
		allocs := make([]float64, 0, len(values))
		for _, value := range values {
			nanoseconds = append(nanoseconds, value.Nanoseconds)
			bytes = append(bytes, value.Bytes)
			allocs = append(allocs, value.Allocs)
		}
		summaries[name] = benchmarkSummary{
			Nanoseconds:    median(nanoseconds),
			latencySamples: nanoseconds,
			Bytes:          median(bytes),
			Allocs:         median(allocs),
		}
	}
	return summaries, nil
}

func parseBenchmarkLine(fields []string) (benchmarkSample, bool) {
	var sample benchmarkSample
	var hasNanoseconds, hasBytes, hasAllocs bool
	for index := 1; index < len(fields); index++ {
		if index == 0 {
			continue
		}
		value, err := strconv.ParseFloat(fields[index-1], 64)
		if err != nil {
			continue
		}
		switch fields[index] {
		case "ns/op":
			sample.Nanoseconds, hasNanoseconds = value, true
		case "B/op":
			sample.Bytes, hasBytes = value, true
		case "allocs/op":
			sample.Allocs, hasAllocs = value, true
		}
	}
	return sample, hasNanoseconds && hasBytes && hasAllocs
}

func benchmarkName(raw string) string {
	index := strings.LastIndexByte(raw, '-')
	if index <= 0 {
		return raw
	}
	if _, err := strconv.Atoi(raw[index+1:]); err == nil {
		return raw[:index]
	}
	return raw
}

func median(values []float64) float64 {
	sort.Float64s(values)
	middle := len(values) / 2
	if len(values)%2 == 1 {
		return values[middle]
	}
	return (values[middle-1] + values[middle]) / 2
}

func compareBenchmarks(base, current map[string]benchmarkSummary, limits tolerances, output io.Writer) error {
	names := make([]string, 0, len(base))
	for name := range base {
		names = append(names, name)
	}
	sort.Strings(names)

	var failures []string
	for _, name := range names {
		baseSummary := base[name]
		currentSummary, ok := current[name]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s is missing from current benchmarks", name))
			continue
		}
		fmt.Fprintf(output, "%s: ns/op %.0f -> %.0f, B/op %.0f -> %.0f, allocs/op %.0f -> %.0f\n",
			name,
			baseSummary.Nanoseconds, currentSummary.Nanoseconds,
			baseSummary.Bytes, currentSummary.Bytes,
			baseSummary.Allocs, currentSummary.Allocs,
		)
		failures = append(failures,
			latencyRegression(name, baseSummary, currentSummary, limits.Latency, output),
			regressionWithAbsoluteSlack(name, "B/op", baseSummary.Bytes, currentSummary.Bytes, limits.Bytes, limits.BytesAbsolute),
			regressionWithAbsoluteSlack(name, "allocs/op", baseSummary.Allocs, currentSummary.Allocs, limits.Allocs, limits.AllocsAbsolute),
		)
	}
	for _, name := range sortedKeys(current) {
		if _, exists := base[name]; !exists {
			fmt.Fprintf(output, "%s: new benchmark in current revision\n", name)
		}
	}

	filtered := failures[:0]
	for _, failure := range failures {
		if failure != "" {
			filtered = append(filtered, failure)
		}
	}
	if len(filtered) > 0 {
		return errors.New(strings.Join(filtered, "; "))
	}
	return nil
}

func regression(name, metric string, base, current, tolerance float64) string {
	if base == 0 {
		if current == 0 {
			return ""
		}
		return fmt.Sprintf("%s %s increased from zero to %.0f", name, metric, current)
	}
	if current <= base*(1+tolerance) {
		return ""
	}
	return fmt.Sprintf("%s %s regressed %.1f%% (%.0f -> %.0f; limit %.1f%%)",
		name, metric, (current/base-1)*100, base, current, tolerance*100)
}

func regressionWithAbsoluteSlack(name, metric string, base, current, relativeTolerance, absoluteTolerance float64) string {
	if current <= base+absoluteTolerance {
		return ""
	}
	return regression(name, metric, base, current, relativeTolerance)
}

func sortedKeys(values map[string]benchmarkSummary) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Require a repeatable latency increase, not just a noisy median. Bootstrap
// independent samples with a fixed seed so CI decisions are reproducible.
// Six samples are required; shorter inputs retain the strict median check.
func latencyRegression(name string, base, current benchmarkSummary, tolerance float64, output io.Writer) string {
	failure := regression(name, "ns/op", base.Nanoseconds, current.Nanoseconds, tolerance)
	if failure == "" || len(base.latencySamples) < 6 || len(current.latencySamples) < 6 || base.Nanoseconds <= 0 {
		return failure
	}
	rng := rand.New(rand.NewSource(1))
	const iterations = 10000
	ratios := make([]float64, iterations)
	b := make([]float64, len(base.latencySamples))
	c := make([]float64, len(current.latencySamples))
	for i := range ratios {
		for j := range b {
			b[j] = base.latencySamples[rng.Intn(len(base.latencySamples))]
		}
		for j := range c {
			c[j] = current.latencySamples[rng.Intn(len(current.latencySamples))]
		}
		baseline := median(b)
		if baseline <= 0 {
			return failure
		}
		ratios[i] = median(c)/baseline - 1
	}
	sort.Float64s(ratios)
	low, high := ratios[iterations/40], ratios[iterations*39/40]
	fmt.Fprintf(output, "%s: latency bootstrap 95%% interval %.1f%% to %.1f%% (limit %.1f%%)\n", name, low*100, high*100, tolerance*100)
	if low <= tolerance {
		return ""
	}
	return failure
}
