package waf

import "time"

const (
	ModeOff       = "off"
	ModeDetection = "detection"
	ModeBlocking  = "blocking"

	DefaultMaxEvents = 1000
	DefaultEventTTL  = 10 * time.Minute
	DefaultLeaseTTL  = 30 * time.Second
)

type EvaluateContext struct {
	TraceID    string
	ClientIP   string
	RouteType  string
	RouteKey   string
	Upstream   string
	Scheme     string
	RemoteAddr string
}

type Decision struct {
	Enabled       bool
	Allowed       bool
	DetectionOnly bool
	TraceID       string
	Status        int
	Mode          string
	Action        string
	BundleID      string
	RuleIDs       []int
	Event         *Event
	Err           error
}

type Event struct {
	TraceID       string            `json:"trace_id"`
	TransactionID string            `json:"transaction_id"`
	Time          string            `json:"time"`
	Mode          string            `json:"mode"`
	Action        string            `json:"action"`
	Status        int               `json:"status,omitempty"`
	ClientIP      string            `json:"client_ip,omitempty"`
	RemoteAddr    string            `json:"remote_addr,omitempty"`
	Method        string            `json:"method,omitempty"`
	Scheme        string            `json:"scheme,omitempty"`
	Host          string            `json:"host,omitempty"`
	Path          string            `json:"path,omitempty"`
	Query         string            `json:"query,omitempty"`
	RequestURI    string            `json:"request_uri,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	Referer       string            `json:"referer,omitempty"`
	RouteType     string            `json:"route_type,omitempty"`
	RouteKey      string            `json:"route_key,omitempty"`
	Upstream      string            `json:"upstream,omitempty"`
	BundleID      string            `json:"bundle_id,omitempty"`
	BundleHash    string            `json:"bundle_hash,omitempty"`
	RuleIDs       []int             `json:"rule_ids,omitempty"`
	Rules         []RuleMatch       `json:"rules,omitempty"`
	Interruption  *InterruptionInfo `json:"interruption,omitempty"`
	Error         string            `json:"error,omitempty"`
}

type RuleMatch struct {
	ID               int               `json:"id"`
	Message          string            `json:"message,omitempty"`
	Data             string            `json:"data,omitempty"`
	Severity         string            `json:"severity,omitempty"`
	Phase            int               `json:"phase,omitempty"`
	File             string            `json:"file,omitempty"`
	Line             int               `json:"line,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	Disruptive       bool              `json:"disruptive"`
	MatchedVariables []MatchedVariable `json:"matched_variables,omitempty"`
}

type MatchedVariable struct {
	Variable     string `json:"variable,omitempty"`
	Key          string `json:"key,omitempty"`
	ValuePreview string `json:"value_preview,omitempty"`
}

type InterruptionInfo struct {
	RuleID int    `json:"rule_id,omitempty"`
	Action string `json:"action,omitempty"`
	Status int    `json:"status,omitempty"`
}

type Status struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`
	Loaded        bool   `json:"loaded"`
	BundleID      string `json:"bundle_id,omitempty"`
	BundleHash    string `json:"bundle_hash,omitempty"`
	LoadedAt      string `json:"loaded_at,omitempty"`
	RulesDir      string `json:"rules_dir,omitempty"`
	PendingEvents int    `json:"pending_events"`
	LastError     string `json:"last_error,omitempty"`
}

type ValidationResult struct {
	OK         bool   `json:"ok"`
	BundleID   string `json:"bundle_id,omitempty"`
	BundlePath string `json:"bundle_path,omitempty"`
	BundleHash string `json:"bundle_hash,omitempty"`
	Error      string `json:"error,omitempty"`
}

type DrainResult struct {
	Events       []Event `json:"events"`
	Drained      int     `json:"drained"`
	Remaining    int     `json:"remaining"`
	LeaseID      string  `json:"lease_id,omitempty"`
	Acknowledged int     `json:"acknowledged,omitempty"`
}
