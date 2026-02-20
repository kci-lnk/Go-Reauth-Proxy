package models

type Rule struct {
	Path        string `json:"path" example:"/api"`                           // Path prefix to match (e.g., "/api")
	Target      string `json:"target" example:"http://localhost:8080"`        // Target URL (e.g., "http://localhost:9091")
	AuthURL     string `json:"auth_url" example:"http://auth-service/verify"` // External Auth Verification URL. If empty, no auth.
	LoginURL    string `json:"login_url" example:"http://auth-service/login"` // Redirect URL on auth failure.
	StripPath   bool   `json:"strip_path" example:"true"`                     // If true, strips the Path prefix from the request before forwarding.
	RewriteHTML bool   `json:"rewrite_html" example:"true"`                   // If true, rewrites absolute paths in HTML response to include Path prefix.
	UseRootMode bool   `json:"use_root_mode" example:"false"`                 // If true, sets cookie and redirects matched path to /.
}

type PortConfig struct {
	Port  int    `json:"port"`
	Rules []Rule `json:"rules"`
}
