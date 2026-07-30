package waf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	benchmarkWAFBytesSink []byte
	benchmarkWAFIDsSink   map[int]struct{}

	ruleIDActionLegacyRe            = regexp.MustCompile(`(?i)\bid\s*:\s*(\d+)\b`)
	secRuleUpdateTargetByIDLegacyRe = regexp.MustCompile(`(?i)^SecRuleUpdateTargetById\s+(\d+)\b`)
)

func TestFilterMissingUpdateTargetDirectivesMatchesLegacy(t *testing.T) {
	defined := map[int]struct{}{
		1001: {},
		1002: {},
	}
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "no change",
			raw:  "SecRuleUpdateTargetById 1001 \"!ARGS:ok\"\n",
		},
		{
			name: "missing rule with newline",
			raw:  "SecRuleUpdateTargetById 9999 \"!ARGS:skip\"\n",
		},
		{
			name: "missing rule without trailing newline",
			raw:  "SecRuleUpdateTargetById 9999 \"!ARGS:skip\"",
		},
		{
			name: "comments and blanks preserved",
			raw:  "# SecRuleUpdateTargetById 9999 \"!ARGS:skip\"\n\nSecRuleUpdateTargetById 1002 \"!ARGS:ok\"\n",
		},
		{
			name: "case insensitive directive with tab",
			raw:  " secruleupdatetargetbyid\t9999 \"!ARGS:skip\"\n",
		},
		{
			name: "crlf skipped line uses legacy newline",
			raw:  "SecRuleUpdateTargetById 9999 \"!ARGS:skip\"\r\nSecRuleUpdateTargetById 1001 \"!ARGS:ok\"\r\n",
		},
		{
			name: "word boundary keeps suffixed id",
			raw:  "SecRuleUpdateTargetById 9999abc \"!ARGS:keep\"\nSecRuleUpdateTargetById 9999_ \"!ARGS:keep\"\nSecRuleUpdateTargetById 9999-foo \"!ARGS:skip\"\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := filterMissingUpdateTargetDirectives([]byte(tc.raw), defined)
			want, wantChanged := filterMissingUpdateTargetDirectivesLegacyForBenchmark([]byte(tc.raw), defined)
			if changed != wantChanged {
				t.Fatalf("changed = %v, want %v", changed, wantChanged)
			}
			if string(got) != string(want) {
				t.Fatalf("filtered output = %q, want %q", got, want)
			}
		})
	}
}

func TestCollectDefinedRuleIDsMatchesLegacy(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "rules.conf")
	txtPath := filepath.Join(dir, "ignored.txt")
	raw := strings.Join([]string{
		"# SecRule ARGS:test \"@streq attack\" \"id:1,phase:2,deny\"",
		"SecRule ARGS:test \"@streq attack\" \"id:1001,phase:2,deny\"",
		"SecAction \"ID : 1002,phase:1,pass,nolog\"",
		"SecRule ARGS:test \"@rx attack\" \"ruleid:77,id:1003abc,id:1004-foo,id:1005_foo\"",
		"SecRule ARGS:test \"@rx attack\" \"msg:'two ids',id:1006,id:1007\"",
		"",
	}, "\n")
	if err := os.WriteFile(confPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	if err := os.WriteFile(txtPath, []byte("SecAction \"id:9999,pass\"\n"), 0o644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}
	targets := []loadTarget{
		{kind: loadFile, path: confPath},
		{kind: loadFile, path: txtPath},
		{kind: loadFile},
	}

	got, err := collectDefinedRuleIDs(targets)
	if err != nil {
		t.Fatalf("collect ids: %v", err)
	}
	want, err := collectDefinedRuleIDsLegacyForBenchmark(targets)
	if err != nil {
		t.Fatalf("legacy collect ids: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("collected ids = %#v, want %#v", got, want)
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			t.Fatalf("missing id %d in %#v", id, got)
		}
	}
}

func TestReadLimitedEnforcesMaximumSize(t *testing.T) {
	const limit = int64(8)

	got, err := readLimited(bytes.NewReader([]byte("12345678")), limit, "rules.conf")
	if err != nil {
		t.Fatalf("read exact limit: %v", err)
	}
	if string(got) != "12345678" {
		t.Fatalf("read exact limit = %q", got)
	}

	if _, err := readLimited(bytes.NewReader([]byte("123456789")), limit, "rules.conf"); err == nil {
		t.Fatal("expected oversized rule file to be rejected")
	}
}

func BenchmarkFilterMissingUpdateTargetDirectivesNoChange(b *testing.B) {
	raw, defined := makeWAFLoaderFixture(2000, 0)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		filtered, changed := filterMissingUpdateTargetDirectives(raw, defined)
		benchmarkWAFBytesSink = filtered
		benchmarkWAFBoolSink = changed
	}
}

func BenchmarkFilterMissingUpdateTargetDirectivesNoChangeOld(b *testing.B) {
	raw, defined := makeWAFLoaderFixture(2000, 0)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		filtered, changed := filterMissingUpdateTargetDirectivesLegacyForBenchmark(raw, defined)
		benchmarkWAFBytesSink = filtered
		benchmarkWAFBoolSink = changed
	}
}

func BenchmarkFilterMissingUpdateTargetDirectivesChanged(b *testing.B) {
	raw, defined := makeWAFLoaderFixture(2000, 32)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		filtered, changed := filterMissingUpdateTargetDirectives(raw, defined)
		benchmarkWAFBytesSink = filtered
		benchmarkWAFBoolSink = changed
	}
}

func BenchmarkFilterMissingUpdateTargetDirectivesChangedOld(b *testing.B) {
	raw, defined := makeWAFLoaderFixture(2000, 32)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		filtered, changed := filterMissingUpdateTargetDirectivesLegacyForBenchmark(raw, defined)
		benchmarkWAFBytesSink = filtered
		benchmarkWAFBoolSink = changed
	}
}

func BenchmarkCollectDefinedRuleIDs(b *testing.B) {
	targets, totalBytes := makeWAFLoaderRuleTargets(b, 4000)
	b.SetBytes(totalBytes)
	b.ReportAllocs()
	for b.Loop() {
		ids, err := collectDefinedRuleIDs(targets)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkWAFIDsSink = ids
	}
}

func BenchmarkCollectDefinedRuleIDsOld(b *testing.B) {
	targets, totalBytes := makeWAFLoaderRuleTargets(b, 4000)
	b.SetBytes(totalBytes)
	b.ReportAllocs()
	for b.Loop() {
		ids, err := collectDefinedRuleIDsLegacyForBenchmark(targets)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkWAFIDsSink = ids
	}
}

func makeWAFLoaderFixture(ruleCount int, missingEvery int) ([]byte, map[int]struct{}) {
	var builder strings.Builder
	defined := make(map[int]struct{}, ruleCount)
	for i := 0; i < ruleCount; i++ {
		id := 930000 + i
		defined[id] = struct{}{}
		fmt.Fprintf(&builder, "SecRule REQUEST_HEADERS:User-Agent \"@contains attack-%d\" \"id:%d,phase:1,pass,nolog\"\n", i, id)
		updateID := id
		if missingEvery > 0 && i%missingEvery == 0 {
			updateID = 990000 + i
		}
		fmt.Fprintf(&builder, "SecRuleUpdateTargetById %d \"!ARGS:ignored_%d\"\n", updateID, i)
		if i%10 == 0 {
			builder.WriteString("# SecRuleUpdateTargetById 999999 \"!ARGS:comment\"\n\n")
		}
	}
	return []byte(builder.String()), defined
}

func makeWAFLoaderRuleTargets(b *testing.B, ruleCount int) ([]loadTarget, int64) {
	b.Helper()
	dir := b.TempDir()
	raw, _ := makeWAFLoaderFixture(ruleCount, 0)
	confPath := filepath.Join(dir, "rules.conf")
	if err := os.WriteFile(confPath, raw, 0o644); err != nil {
		b.Fatalf("write benchmark conf: %v", err)
	}
	txtPath := filepath.Join(dir, "ignored.txt")
	if err := os.WriteFile(txtPath, []byte("SecAction \"id:999999,pass\"\n"), 0o644); err != nil {
		b.Fatalf("write benchmark ignored file: %v", err)
	}
	return []loadTarget{{kind: loadFile, path: confPath}, {kind: loadFile, path: txtPath}}, int64(len(raw))
}

func filterMissingUpdateTargetDirectivesLegacyForBenchmark(raw []byte, definedRuleIDs map[int]struct{}) ([]byte, bool) {
	var out strings.Builder
	changed := false
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out.WriteString(line)
			continue
		}
		match := secRuleUpdateTargetByIDLegacyRe.FindStringSubmatch(trimmed)
		if len(match) == 2 {
			id, err := strconv.Atoi(match[1])
			if err == nil {
				if _, ok := definedRuleIDs[id]; !ok {
					changed = true
					out.WriteString("# fn-knock skipped SecRuleUpdateTargetById ")
					out.WriteString(match[1])
					out.WriteString(" because the target rule is not enabled")
					if strings.HasSuffix(line, "\n") {
						out.WriteString("\n")
					}
					continue
				}
			}
		}
		out.WriteString(line)
	}
	return []byte(out.String()), changed
}

func collectDefinedRuleIDsLegacyForBenchmark(targets []loadTarget) (map[int]struct{}, error) {
	ids := map[int]struct{}{}
	for _, target := range targets {
		if target.path == "" || !strings.EqualFold(filepath.Ext(target.path), ".conf") {
			continue
		}
		raw, err := os.ReadFile(target.path)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, match := range ruleIDActionLegacyRe.FindAllStringSubmatch(line, -1) {
				id, err := strconv.Atoi(match[1])
				if err == nil {
					ids[id] = struct{}{}
				}
			}
		}
	}
	return ids, nil
}
