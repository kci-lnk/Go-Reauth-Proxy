package models

type Rule struct {
	Path        string `json:"path" example:"/api"`                    // Path prefix to match (e.g., "/api")
	Target      string `json:"target" example:"http://localhost:8080"` // Target URL (e.g., "http://localhost:7996")
	UseAuth     bool   `json:"use_auth" example:"false"`               // If true, invokes global authentication check before proxying.
	StripPath   bool   `json:"strip_path" example:"true"`              // If true, strips the Path prefix from the request before forwarding.
	RewriteHTML bool   `json:"rewrite_html" example:"true"`            // If true, rewrites absolute paths in HTML response to include Path prefix.
	UseRootMode bool   `json:"use_root_mode" example:"false"`          // If true, sets cookie and redirects matched path to /.
}

type AuthConfig struct {
	AuthPort  int    `json:"auth_port" example:"3000"`              // Local Auth Service Port
	AuthURL   string `json:"auth_url" example:"/api/auth/verify"`   // Relative Verify URL (default /api/auth/verify)
	LoginURL  string `json:"login_url" example:"/login"`            // Relative Login URL (default /login)
	LogoutURL string `json:"logout_url" example:"/api/auth/logout"` // Relative Logout URL (default /api/auth/logout)
}

type PortConfig struct {
	Port  int    `json:"port"`
	Rules []Rule `json:"rules"`
}

type SSLInfo struct {
	Enabled bool `json:"enabled"`
}

type SSLRequest struct {
	Cert string `json:"cert" example:"-----BEGIN CERTIFICATE-----\n..."`
	Key  string `json:"key" example:"-----BEGIN RSA PRIVATE KEY-----\n..."`
}
