package proxy

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestStripAdvancedAuthGrantCookieNormalizesEmptySegmentsForUpstreamLimit(t *testing.T) {
	// Make the upstream parser limit explicit; the gateway fix does not need
	// to know it and must preserve normalization independently of its value.
	t.Setenv("GODEBUG", "httpcookiemaxnum=3000")
	for _, empty := range []string{";", "; ", ";\t"} {
		t.Run(empty, func(t *testing.T) {
			request := &http.Request{Header: http.Header{
				"Cookie": {"sid=ok" + strings.Repeat(empty, 3000)},
			}}
			if cookies := request.Cookies(); len(cookies) != 0 {
				t.Fatal("fixture must exceed the upstream parser's raw segment limit")
			}
			stripAdvancedAuthGrantCookie(request.Header)
			cookie, err := request.Cookie("sid")
			if err != nil || cookie.Value != "ok" {
				t.Fatalf("ordinary cookie was lost at the upstream parser: cookie=%v error=%v", cookie, err)
			}
			if got := request.Header.Values("Cookie"); !reflect.DeepEqual(got, []string{"sid=ok"}) {
				t.Fatalf("normalized Cookie = %q, want [sid=ok]", got)
			}
		})
	}
}

func TestStripAdvancedAuthGrantCookieNormalizesEmptySegments(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		output string
	}{
		{"empty", "", ""},
		{"whitespace only", " \t", ""},
		{"leading", "; sid=ok", "sid=ok"},
		{"middle", "sid=ok;;theme=dark", "sid=ok; theme=dark"},
		{"space segment", "sid=ok; ;theme=dark", "sid=ok; theme=dark"},
		{"tab segment", "sid=ok;\t;theme=dark", "sid=ok; theme=dark"},
		{"unicode whitespace segment", "sid=ok;\u00a0;theme=dark", "sid=ok; theme=dark"},
		{"trailing", "sid=ok;", "sid=ok"},
		{"trailing whitespace", "sid=ok; \t", "sid=ok"},
		{"unicode prefix", "\u00a0sid=ok", "sid=ok"},
		{"unicode suffix", "sid=ok\u00a0", "sid=ok"},
		{"mixed boundary spaces", "sid=ok; \u00a0theme=dark\u00a0 ", "sid=ok; theme=dark"},
		{"vertical tab helper input", "sid=ok\v", "sid=ok"},
		{"form feed helper input", "\fsid=ok", "sid=ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"cookie": {tc.input}}
			stripAdvancedAuthGrantCookie(headers)
			var want []string
			if tc.output != "" {
				want = []string{tc.output}
			}
			if got := headers.Values("Cookie"); !reflect.DeepEqual(got, want) {
				t.Fatalf("normalized Cookie = %q, want %q", got, want)
			}
			if _, exists := headers["cookie"]; exists {
				t.Fatal("rewritten request kept the noncanonical source key")
			}
		})
	}
}
