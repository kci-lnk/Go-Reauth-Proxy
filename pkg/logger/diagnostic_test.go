package logger

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRotatingDiagnosticWriterBoundsAndPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "gateway.jsonl")
	if err := os.WriteFile(path, bytes.Repeat([]byte("c"), 128), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", bytes.Repeat([]byte("p"), 128), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, err := newRotatingDiagnosticWriter(path, 64)
	if err != nil {
		t.Fatalf("newRotatingDiagnosticWriter: %v", err)
	}
	for _, file := range []string{path, path + ".1"} {
		if info, err := os.Stat(file); err != nil || info.Size() > 64 {
			t.Fatalf("historical %s was not capped: info=%v err=%v", file, info, err)
		}
	}
	line := append(bytes.Repeat([]byte("x"), 39), '\n')
	if _, err := writer.Write(line); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := writer.Write(line); err != nil {
		t.Fatalf("write rotating: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, file := range []string{path, path + ".1"} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatalf("stat %s: %v", file, err)
		}
		if info.Size() > 64 {
			t.Fatalf("%s size = %d, want <= 64", file, info.Size())
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o, want 600", file, info.Mode().Perm())
		}
	}
}

func TestRotatingDiagnosticWriterObservesExternalTruncate(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "gateway.jsonl")
	writer, err := newRotatingDiagnosticWriter(path, 64)
	if err != nil {
		t.Fatalf("newRotatingDiagnosticWriter: %v", err)
	}
	defer writer.Close()
	if _, err := writer.Write(bytes.Repeat([]byte("a"), 48)); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("b"), 32)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 32 {
		t.Fatalf("size after external truncate = %d, want 32", info.Size())
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("external truncate caused an unnecessary rotation: %v", err)
	}
}

func TestDiagnosticFieldsAreAllowListedAndRedacted(t *testing.T) {
	fields := cleanDiagnosticFields(map[string]any{
		"pid":           42,
		"listener":      "https://user:pass@example.com/private?q=secret#fragment",
		"authorization": "Bearer canary",
		"config":        "/private/config.json",
	})
	if fields["pid"] != 42 {
		t.Fatalf("pid was not preserved: %#v", fields)
	}
	listener := fields["listener"].(string)
	if strings.Contains(listener, "example.com") || strings.Contains(listener, "user:pass") || strings.Contains(listener, "secret") {
		t.Fatalf("listener was not redacted: %q", listener)
	}
	if _, ok := fields["authorization"]; ok {
		t.Fatalf("authorization field was retained: %#v", fields)
	}
	if _, ok := fields["config"]; ok {
		t.Fatalf("config field was retained: %#v", fields)
	}
}

func TestCrashOutputCapturesUnhandledPanic(t *testing.T) {
	const childEnv = "FN_KNOCK_DIAGNOSTIC_CRASH_TEST_CHILD"
	if os.Getenv(childEnv) == "1" {
		runtime, err := newDiagnosticRuntime(os.Getenv(DiagnosticLogDirEnv))
		if err != nil {
			panic(err)
		}
		_ = runtime
		panic("diagnostic-crash-canary")
	}

	directory := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestCrashOutputCapturesUnhandledPanic$")
	command.Env = append(os.Environ(), childEnv+"=1", DiagnosticLogDirEnv+"="+directory)
	if err := command.Run(); err == nil {
		t.Fatal("child panic unexpectedly succeeded")
	}
	crash, err := os.ReadFile(filepath.Join(directory, "gateway-crash.log"))
	if err != nil {
		t.Fatalf("read crash output: %v", err)
	}
	if !strings.Contains(string(crash), "diagnostic-crash-canary") {
		t.Fatalf("panic was not captured: %q", crash)
	}
}

func TestCrashFileCapKeepsNewestTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway-crash.log")
	content := strings.Repeat("old-line\n", 20) + "latest-crash-line\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := capCrashFile(path, 64); err != nil {
		t.Fatal(err)
	}
	capped, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) > 64 || !strings.Contains(string(capped), "latest-crash-line") {
		t.Fatalf("unexpected capped crash output: %q", capped)
	}
}

func TestDiagnosticRepeatStateHasTTLAndHardLimit(t *testing.T) {
	runtime := &diagnosticRuntime{repeats: make(map[string]repeatState)}
	now := time.Now()
	for index := 0; index < diagnosticRepeatMax+100; index++ {
		if _, emit := runtime.aggregateRepeat(now.Add(time.Duration(index)), fmt.Sprintf("key-%d", index)); !emit {
			t.Fatalf("new key %d was unexpectedly suppressed", index)
		}
	}
	if len(runtime.repeats) != diagnosticRepeatMax {
		t.Fatalf("repeat entries = %d, want %d", len(runtime.repeats), diagnosticRepeatMax)
	}
	runtime.repeats["expired"] = repeatState{last: now.Add(-diagnosticRepeatTTL - time.Second)}
	runtime.aggregateRepeat(now, "current")
	if _, exists := runtime.repeats["expired"]; exists {
		t.Fatal("expired repeat entry was retained")
	}

	firstCount, firstEmit := runtime.aggregateRepeat(now, "aggregate")
	_, secondEmit := runtime.aggregateRepeat(now.Add(time.Second), "aggregate")
	aggregatedCount, thirdEmit := runtime.aggregateRepeat(now.Add(diagnosticRepeatWindow+time.Second), "aggregate")
	if !firstEmit || firstCount != 1 || secondEmit || !thirdEmit || aggregatedCount != 2 {
		t.Fatalf(
			"unexpected aggregation: first=(%d,%v), second=%v, third=(%d,%v)",
			firstCount,
			firstEmit,
			secondEmit,
			aggregatedCount,
			thirdEmit,
		)
	}
}
