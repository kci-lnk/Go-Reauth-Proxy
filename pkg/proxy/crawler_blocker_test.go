package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCrawlerBlockerDisabledDoesNotBlockCrawlerUserAgent(t *testing.T) {
	handler := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/", nil)
	req.Header.Set("User-Agent", "GPTBot")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("disabled crawler blocker returned forbidden")
	}
	if got := rec.Header().Get("X-Fn-Knock-Crawler-Blocked"); got != "" {
		t.Fatalf("crawler blocked header = %q, want empty", got)
	}
}

func TestCrawlerBlockerServesRobotsBeforeUserAgentBlock(t *testing.T) {
	handler := &Handler{
		CrawlerBlocker: models.CrawlerBlockerConfig{Enabled: true},
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/robots.txt", nil)
	req.Header.Set("User-Agent", "GPTBot")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("content type = %q, want text/plain", contentType)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"User-agent: *\nDisallow: /",
		"User-agent: GPTBot\nDisallow: /",
		"User-agent: BLEXBot\nDisallow: /",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("robots.txt missing %q in body:\n%s", want, body)
		}
	}
	if got := rec.Header().Get("X-Fn-Knock-Crawler-Blocked"); got != "" {
		t.Fatalf("crawler blocked header = %q, want empty for robots.txt", got)
	}
}

func TestCrawlerBlockerBlocksKnownCrawlerUserAgents(t *testing.T) {
	handler := &Handler{
		CrawlerBlocker: models.CrawlerBlockerConfig{Enabled: true},
	}

	tests := []string{
		"GPTBot",
		"mozilla gPtBoT",
		"Sogou web spider",
	}
	for _, userAgent := range tests {
		t.Run(userAgent, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/private", nil)
			req.Header.Set("User-Agent", userAgent)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Get("X-Fn-Knock-Crawler-Blocked"); got != "1" {
				t.Fatalf("crawler blocked header = %q, want 1", got)
			}
		})
	}
}

func TestCrawlerBlockerAllowsNonCrawlerUserAgent(t *testing.T) {
	handler := &Handler{
		CrawlerBlocker: models.CrawlerBlockerConfig{Enabled: true},
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("non-crawler user agent returned forbidden")
	}
	if got := rec.Header().Get("X-Fn-Knock-Crawler-Blocked"); got != "" {
		t.Fatalf("crawler blocked header = %q, want empty", got)
	}
}
