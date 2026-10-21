package waf

import (
	"io"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// Exercise the gateway's header ingestion and body restoration as well as
// Coraza's parser selection (GHSA-w253-m66g-rx24).
func TestRuntimeFormContentTypeSecurityRegression(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `SecRule ARGS_POST:test "@streq attack" "id:1001,phase:2,deny,status:403,log"`)
	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"plain", []string{"application/x-www-form-urlencoded"}},
		{"charset", []string{"application/x-www-form-urlencoded; charset=UTF-8"}},
		{"whitespace", []string{" application/x-www-form-urlencoded; charset=UTF-8"}},
		{"duplicate", []string{"application/x-www-form-urlencoded", "text/plain"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reuse the runtime for blocked and allowed traffic to cover pooled
			// transactions without changing the bytes forwarded upstream.
			for _, value := range []string{"attack", "safe", "attack"} {
				body := "test=" + value
				req := httptest.NewRequest("POST", "https://app.example.test/form", strings.NewReader(body))
				for _, header := range tc.headers {
					req.Header.Add("Content-Type", header)
				}
				decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
				wantBlocked := value == "attack"
				if decision.Err != nil || decision.Allowed == wantBlocked {
					t.Fatalf("body %q: unexpected decision: %#v", body, decision)
				}
				if wantBlocked && (decision.Status != 403 || !slices.Contains(decision.RuleIDs, 1001)) {
					t.Fatalf("expected form rule to block: %#v", decision)
				}
				restored, err := io.ReadAll(req.Body)
				_ = req.Body.Close()
				if err != nil || string(restored) != body {
					t.Fatalf("forwarded body = %q, err = %v; want %q", restored, err, body)
				}
			}
		})
	}
}

// Case-distinct JSON keys must all be inspected, regardless of their order
// (GHSA-5gj4-9gm7-2fx2).
func TestRuntimeJSONKeyCollisionSecurityRegression(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `
SecAction "id:1002,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule ARGS_POST "@streq attack" "id:1001,phase:2,deny,status:403,log"
`)
	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body    string
		blocked bool
	}{
		{`{"key":"attack","KEY":"safe"}`, true},
		{`{"KEY":"safe","key":"attack"}`, true},
		{`{"key":"safe","KEY":"also-safe"}`, false},
	} {
		t.Run(tc.body, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://app.example.test/json", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
			if decision.Err != nil || decision.Allowed == tc.blocked {
				t.Fatalf("unexpected decision: %#v", decision)
			}
			if tc.blocked && !slices.Contains(decision.RuleIDs, 1001) {
				t.Fatalf("expected JSON rule to block: %#v", decision)
			}
			restored, err := io.ReadAll(req.Body)
			_ = req.Body.Close()
			if err != nil || string(restored) != tc.body {
				t.Fatalf("forwarded body = %q, err = %v; want %q", restored, err, tc.body)
			}
		})
	}
}

// Keep the input small: exceeding a configured depth must be reported even
// after the argument budget is exhausted, without a stack-exhaustion payload.
func TestRuntimeJSONDepthAfterArgumentLimitSecurityRegression(t *testing.T) {
	rulesDir := t.TempDir()
	writeTestRule(t, rulesDir, `
SecArgumentsLimit 2
SecRequestBodyJsonDepthLimit 8
SecAction "id:1002,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"
SecRule REQBODY_ERROR "@eq 1" "id:1001,phase:2,deny,status:400,log"
`)
	rt := NewRuntime(testConfig(rulesDir, ModeBlocking), t.TempDir())
	if _, err := rt.Reload(rt.Config(), "", ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		body    string
		blocked bool
	}{
		{"deep tail", "[1,2," + strings.Repeat("[", 20) + "0" + strings.Repeat("]", 20) + "]", true},
		{"ordinary JSON", "[1,2]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "https://app.example.test/json", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			decision := rt.Evaluate(req, EvaluateContext{ClientIP: "203.0.113.10"})
			if decision.Allowed == tc.blocked {
				t.Fatalf("unexpected decision: %#v", decision)
			}
			if tc.blocked && (decision.Status != 400 || !slices.Contains(decision.RuleIDs, 1001)) {
				t.Fatalf("expected JSON body error rule to block: %#v", decision)
			}
			_ = req.Body.Close()
		})
	}
}
