package proxy

import (
	"go-reauth-proxy/pkg/models"
	"net/http"
	"strings"
)

const crawlerBlockerRobotsPath = "/robots.txt"

const crawlerBlockerRobotsContent = `User-agent: *
Disallow: /

User-agent: GPTBot
Disallow: /

User-agent: OAI-SearchBot
Disallow: /

User-agent: ChatGPT-User
Disallow: /

User-agent: Google-Extended
Disallow: /

User-agent: ClaudeBot
Disallow: /

User-agent: Claude-SearchBot
Disallow: /

User-agent: Claude-User
Disallow: /

User-agent: CCBot
Disallow: /

User-agent: PerplexityBot
Disallow: /

User-agent: Perplexity-User
Disallow: /

User-agent: Googlebot
Disallow: /

User-agent: Bingbot
Disallow: /

User-agent: Slurp
Disallow: /

User-agent: DuckDuckBot
Disallow: /

User-agent: YandexBot
Disallow: /

User-agent: Baiduspider
Disallow: /

User-agent: Sogou web spider
Disallow: /

User-agent: 360Spider
Disallow: /

User-agent: Bytespider
Disallow: /

User-agent: Amazonbot
Disallow: /

User-agent: Applebot
Disallow: /

User-agent: Applebot-Extended
Disallow: /

User-agent: Meta-ExternalAgent
Disallow: /

User-agent: FacebookBot
Disallow: /

User-agent: Diffbot
Disallow: /

User-agent: YouBot
Disallow: /

User-agent: cohere-ai
Disallow: /

User-agent: Timpibot
Disallow: /

User-agent: omgili
Disallow: /

User-agent: omgilibot
Disallow: /

User-agent: ImagesiftBot
Disallow: /

User-agent: PetalBot
Disallow: /

User-agent: SemrushBot
Disallow: /

User-agent: AhrefsBot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: DotBot
Disallow: /

User-agent: BLEXBot
Disallow: /
`

var crawlerBlockerUserAgentTokens = []string{
	"gptbot",
	"oai-searchbot",
	"chatgpt-user",
	"oai-adsbot",
	"claudebot",
	"claude-searchbot",
	"claude-user",
	"ccbot",
	"perplexitybot",
	"perplexity-user",
	"google-extended",
	"googlebot",
	"googlebot-image",
	"googlebot-video",
	"googlebot-news",
	"googleother",
	"googleother-image",
	"googleother-video",
	"google-inspectiontool",
	"google-cloudvertexbot",
	"bingbot",
	"bingpreview",
	"slurp",
	"duckduckbot",
	"yandexbot",
	"baiduspider",
	"sogou",
	"360spider",
	"bytespider",
	"applebot",
	"applebot-extended",
	"amazonbot",
	"facebookbot",
	"meta-externalagent",
	"diffbot",
	"youbot",
	"cohere-ai",
	"timpibot",
	"omgili",
	"omgilibot",
	"imagesiftbot",
	"petalbot",
	"semrushbot",
	"ahrefsbot",
	"mj12bot",
	"dotbot",
	"blexbot",
}

func normalizeCrawlerBlockerConfig(cfg models.CrawlerBlockerConfig) models.CrawlerBlockerConfig {
	return models.CrawlerBlockerConfig{
		Enabled:   cfg.Enabled,
		UpdatedAt: strings.TrimSpace(cfg.UpdatedAt),
	}
}

func isCrawlerBlockerRobotsPath(requestPath string) bool {
	return requestPath == crawlerBlockerRobotsPath
}

func isCrawlerBlockerUserAgent(userAgent string) bool {
	normalized := strings.ToLower(strings.TrimSpace(userAgent))
	if normalized == "" {
		return false
	}

	for _, token := range crawlerBlockerUserAgentTokens {
		if strings.Contains(normalized, token) {
			return true
		}
	}
	return false
}

func serveCrawlerBlockerRobots(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(crawlerBlockerRobotsContent))
}

func serveCrawlerBlockerForbidden(w http.ResponseWriter) {
	w.Header().Set("X-Fn-Knock-Crawler-Blocked", "1")
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
