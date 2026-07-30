package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"go-reauth-proxy/pkg/grpc/pb"
	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
)

const (
	// advancedAuthGrantCookieName is intentionally host-only.  The Rust auth
	// service owns issuance and revocation; the gateway only treats this name
	// as an opaque credential and must never forward it to an application.
	advancedAuthGrantCookieName    = "fn-knock-subdomain-rule-grant"
	advancedAuthDefaultIdleSeconds = int64(24 * 60 * 60)
	advancedAuthDefaultMaxSeconds  = int64(30 * 24 * 60 * 60)
	advancedAuthMinSeconds         = int64(5 * 60)
	advancedAuthMaxIdleSeconds     = int64(30 * 24 * 60 * 60)
	advancedAuthMaxLifetimeSeconds = int64(365 * 24 * 60 * 60)
	advancedAuthMaxGroups          = 16
	advancedAuthMaxConditions      = 16
	advancedAuthMaxValues          = 256
	advancedAuthMaxTotalValues     = 4_096
	advancedAuthMaxTotalRegexes    = 256
	advancedAuthMaxRegexBytes      = 512
	advancedAuthMaxCIDRs           = 100_000
	advancedAuthMaxConfigBytes     = 8 * 1024 * 1024
)

// stripAdvancedAuthGrantCookie removes the gateway-only temporary grant from
// an outbound request.  ReverseProxy copies inbound headers before its Rewrite
// callback, so this must run after the proxy request has been built.  Keep all
// unrelated cookies (including ordinary login/share cookies) intact.
func stripAdvancedAuthGrantCookie(headers http.Header) {
	if headers == nil {
		return
	}
	values, exists := advancedAuthHeaderValues(headers, "Cookie")
	if !exists || len(values) == 0 {
		return
	}
	kept := make([]string, 0, len(values))
	for _, header := range values {
		parts := strings.Split(header, ";")
		remaining := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			name, _, ok := strings.Cut(trimmed, "=")
			if ok && strings.EqualFold(strings.TrimSpace(name), advancedAuthGrantCookieName) {
				continue
			}
			if trimmed != "" {
				remaining = append(remaining, trimmed)
			}
		}
		if len(remaining) > 0 {
			kept = append(kept, strings.Join(remaining, "; "))
		}
	}
	for key := range headers {
		if strings.EqualFold(key, "Cookie") {
			delete(headers, key)
		}
	}
	for _, header := range kept {
		headers.Add("Cookie", header)
	}
}

// stripAdvancedAuthGrantSetCookies prevents an application from setting or
// replacing the gateway-only grant.  The auth proxy route deliberately does
// not call this helper: only the auth service may issue or revoke the grant.
func stripAdvancedAuthGrantSetCookies(headers http.Header) {
	if headers == nil {
		return
	}
	values, exists := advancedAuthHeaderValues(headers, "Set-Cookie")
	if !exists || len(values) == 0 {
		return
	}
	for key := range headers {
		if strings.EqualFold(key, "Set-Cookie") {
			delete(headers, key)
		}
	}
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err == nil && strings.EqualFold(cookie.Name, advancedAuthGrantCookieName) {
			continue
		}
		// ParseSetCookie is intentionally best effort.  A malformed upstream
		// header must not become a way to smuggle a reserved cookie name.
		name, _, ok := strings.Cut(value, "=")
		if ok && strings.EqualFold(strings.TrimSpace(name), advancedAuthGrantCookieName) {
			continue
		}
		headers.Add("Set-Cookie", value)
	}
}

type compiledAdvancedAuthPolicy struct {
	enabled            bool
	policyVersion      string
	idleTTLSeconds     int64
	maxLifetimeSeconds int64
	groups             []compiledAdvancedAuthGroup
}

func isEmptyAdvancedAuthConfig(config models.AdvancedAuthConfig) bool {
	return !config.Enabled && config.IdleTTLSeconds == 0 && config.MaxLifetimeSeconds == 0 &&
		strings.TrimSpace(config.PolicyVersion) == "" && len(config.Groups) == 0
}

func copyAdvancedAuthConfig(config models.AdvancedAuthConfig) models.AdvancedAuthConfig {
	copy := config
	copy.Groups = make([]models.AdvancedAuthGroup, len(config.Groups))
	for groupIndex, group := range config.Groups {
		copy.Groups[groupIndex] = group
		copy.Groups[groupIndex].Conditions = make([]models.AdvancedAuthCondition, len(group.Conditions))
		for conditionIndex, condition := range group.Conditions {
			copyCondition := condition
			copyCondition.Values = append([]string(nil), condition.Values...)
			copyCondition.CIDRs = append([]string(nil), condition.CIDRs...)
			copy.Groups[groupIndex].Conditions[conditionIndex] = copyCondition
		}
	}
	return copy
}

type compiledAdvancedAuthGroup struct {
	id         string
	conditions []compiledAdvancedAuthCondition
}

type compiledAdvancedAuthCondition struct {
	target   string
	operator string
	name     string
	values   []string
	valueSet map[string]struct{}
	regexps  []*regexp.Regexp
	ipsets   []*compiledipset.Set
}

type advancedAuthRuleMatch struct {
	host          string
	policyVersion string
	groupID       string
}

type advancedAuthRuleMatchContextKey struct{}
type advancedAuthPolicyVersionContextKey struct{}

func withAdvancedAuthPolicyVersion(request *http.Request, version string) {
	if request == nil {
		return
	}
	*request = *request.WithContext(context.WithValue(request.Context(), advancedAuthPolicyVersionContextKey{}, strings.TrimSpace(version)))
}

func advancedAuthPolicyVersionFromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}
	version, _ := request.Context().Value(advancedAuthPolicyVersionContextKey{}).(string)
	return strings.TrimSpace(version)
}

func withAdvancedAuthRuleMatch(request *http.Request, match *advancedAuthRuleMatch) {
	if request == nil || match == nil {
		return
	}
	*request = *request.WithContext(context.WithValue(request.Context(), advancedAuthRuleMatchContextKey{}, match))
}

func advancedAuthRuleMatchFromRequest(request *http.Request) *advancedAuthRuleMatch {
	if request == nil {
		return nil
	}
	match, _ := request.Context().Value(advancedAuthRuleMatchContextKey{}).(*advancedAuthRuleMatch)
	return match
}

func advancedAuthRuleMatchProto(request *http.Request) *pb.SubdomainRuleMatch {
	match := advancedAuthRuleMatchFromRequest(request)
	if match == nil {
		return nil
	}
	return &pb.SubdomainRuleMatch{
		Host:          match.host,
		PolicyVersion: match.policyVersion,
		GroupId:       match.groupID,
	}
}

func normalizeAdvancedAuthConfig(config models.AdvancedAuthConfig) (models.AdvancedAuthConfig, error) {
	if !config.Enabled && config.PolicyVersion == "" && len(config.Groups) == 0 &&
		config.IdleTTLSeconds == 0 && config.MaxLifetimeSeconds == 0 {
		return models.AdvancedAuthConfig{}, nil
	}
	if config.IdleTTLSeconds == 0 {
		config.IdleTTLSeconds = advancedAuthDefaultIdleSeconds
	}
	if config.MaxLifetimeSeconds == 0 {
		config.MaxLifetimeSeconds = advancedAuthDefaultMaxSeconds
	}
	if config.IdleTTLSeconds < advancedAuthMinSeconds || config.IdleTTLSeconds > advancedAuthMaxIdleSeconds {
		return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth idle TTL must be between 5 minutes and 30 days")
	}
	if config.MaxLifetimeSeconds < advancedAuthMinSeconds || config.MaxLifetimeSeconds > advancedAuthMaxLifetimeSeconds {
		return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth maximum lifetime must be between 5 minutes and 365 days")
	}
	if config.MaxLifetimeSeconds < config.IdleTTLSeconds {
		return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth maximum lifetime cannot be shorter than idle TTL")
	}
	config.PolicyVersion = strings.TrimSpace(config.PolicyVersion)
	if config.Enabled && config.PolicyVersion == "" {
		return models.AdvancedAuthConfig{}, fmt.Errorf("enabled advanced auth requires a policy version")
	}
	if len(config.Groups) > advancedAuthMaxGroups {
		return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth supports at most %d OR groups", advancedAuthMaxGroups)
	}
	if config.Enabled && len(config.Groups) == 0 {
		return models.AdvancedAuthConfig{}, fmt.Errorf("enabled advanced auth requires at least one rule group")
	}

	seenGroups := make(map[string]struct{}, len(config.Groups))
	cidrCount := 0
	totalValueCount := 0
	totalRegexCount := 0
	for groupIndex := range config.Groups {
		group := &config.Groups[groupIndex]
		group.ID = strings.TrimSpace(group.ID)
		if group.ID == "" {
			return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth rule group %d has no id", groupIndex+1)
		}
		if _, exists := seenGroups[group.ID]; exists {
			return models.AdvancedAuthConfig{}, fmt.Errorf("duplicate advanced auth rule group id %q", group.ID)
		}
		seenGroups[group.ID] = struct{}{}
		if len(group.Conditions) == 0 {
			return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth rule group %q is empty", group.ID)
		}
		if len(group.Conditions) > advancedAuthMaxConditions {
			return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth group %q supports at most %d conditions", group.ID, advancedAuthMaxConditions)
		}
		seenConditions := make(map[string]struct{}, len(group.Conditions))
		for conditionIndex := range group.Conditions {
			condition := &group.Conditions[conditionIndex]
			condition.ID = strings.TrimSpace(condition.ID)
			condition.Target = strings.ToLower(strings.TrimSpace(condition.Target))
			condition.Operator = strings.ToLower(strings.TrimSpace(condition.Operator))
			condition.Name = strings.TrimSpace(condition.Name)
			condition.PolicyID = strings.TrimSpace(condition.PolicyID)
			if condition.ID == "" {
				return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth condition %d in group %q has no id", conditionIndex+1, group.ID)
			}
			if _, exists := seenConditions[condition.ID]; exists {
				return models.AdvancedAuthConfig{}, fmt.Errorf("duplicate advanced auth condition id %q in group %q", condition.ID, group.ID)
			}
			seenConditions[condition.ID] = struct{}{}
			if len(condition.Values) > advancedAuthMaxValues {
				return models.AdvancedAuthConfig{}, fmt.Errorf(
					"advanced auth group %q condition %q supports at most %d match values",
					group.ID, condition.ID, advancedAuthMaxValues,
				)
			}
			totalValueCount += len(condition.Values)
			if totalValueCount > advancedAuthMaxTotalValues {
				return models.AdvancedAuthConfig{}, fmt.Errorf(
					"advanced auth supports at most %d match values per host",
					advancedAuthMaxTotalValues,
				)
			}
			if condition.Operator == "regex" || condition.Operator == "not_regex" {
				totalRegexCount += len(condition.Values)
				if totalRegexCount > advancedAuthMaxTotalRegexes {
					return models.AdvancedAuthConfig{}, fmt.Errorf(
						"advanced auth supports at most %d regular expressions per host",
						advancedAuthMaxTotalRegexes,
					)
				}
			}
			if condition.Target == "source_ip" && len(condition.CIDRs) > advancedAuthMaxValues {
				return models.AdvancedAuthConfig{}, fmt.Errorf(
					"advanced auth group %q condition %q supports at most %d source networks",
					group.ID, condition.ID, advancedAuthMaxValues,
				)
			}
			if err := normalizeAdvancedAuthCondition(condition); err != nil {
				return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth group %q condition %q: %w", group.ID, condition.ID, err)
			}
			cidrCount += len(condition.CIDRs)
			if cidrCount > advancedAuthMaxCIDRs {
				return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth resolved CIDRs exceed %d entries", advancedAuthMaxCIDRs)
			}
		}
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return models.AdvancedAuthConfig{}, fmt.Errorf("encode advanced auth configuration: %w", err)
	}
	if len(encoded) > advancedAuthMaxConfigBytes {
		return models.AdvancedAuthConfig{}, fmt.Errorf("advanced auth configuration exceeds %d bytes", advancedAuthMaxConfigBytes)
	}
	return config, nil
}

func normalizeAdvancedAuthCondition(condition *models.AdvancedAuthCondition) error {
	if condition == nil {
		return fmt.Errorf("condition is required")
	}
	switch condition.Target {
	case "source_ip":
		if !slices.Contains([]string{"equals", "not_equals", "in_cidr", "not_in_cidr"}, condition.Operator) {
			return fmt.Errorf("unsupported source IP operator %q", condition.Operator)
		}
		if condition.PolicyID != "" {
			condition.CIDRs = nil
			return nil
		}
		if len(condition.CIDRs) == 0 {
			condition.CIDRs = append([]string(nil), condition.Values...)
		}
		if len(condition.CIDRs) == 0 {
			return fmt.Errorf("source IP condition requires an IP or CIDR")
		}
		seenNetworks := make(map[string]struct{}, len(condition.CIDRs))
		networks := make([]string, 0, len(condition.CIDRs))
		for index, value := range condition.CIDRs {
			normalized, err := canonicalAdvancedAuthNetwork(value, condition.Operator == "equals" || condition.Operator == "not_equals")
			if err != nil {
				return fmt.Errorf("source IP entry %d: %w", index+1, err)
			}
			if _, exists := seenNetworks[normalized]; exists {
				continue
			}
			seenNetworks[normalized] = struct{}{}
			networks = append(networks, normalized)
		}
		condition.CIDRs = networks
		condition.Values = nil
	case "source_region":
		if condition.Operator != "in" && condition.Operator != "not_in" {
			return fmt.Errorf("unsupported source region operator %q", condition.Operator)
		}
		if condition.PolicyID != "" {
			condition.CIDRs = nil
			return nil
		}
		if len(condition.CIDRs) == 0 {
			return fmt.Errorf("source region condition resolved to no CIDRs")
		}
		for index, value := range condition.CIDRs {
			normalized, err := canonicalAdvancedAuthNetwork(value, false)
			if err != nil {
				return err
			}
			condition.CIDRs[index] = normalized
		}
	case "url_path":
		if !isAdvancedAuthTextOperator(condition.Operator, true) {
			return fmt.Errorf("unsupported URL path operator %q", condition.Operator)
		}
		condition.Name = ""
		if err := validateAdvancedAuthTextValues(condition); err != nil {
			return err
		}
	case "request_header":
		condition.Name = http.CanonicalHeaderKey(condition.Name)
		if condition.Name == "" || !validAdvancedAuthHeaderName(condition.Name) {
			return fmt.Errorf("header name is empty, invalid, or protected")
		}
		if !isAdvancedAuthTextOperator(condition.Operator, false) {
			return fmt.Errorf("unsupported Header operator %q", condition.Operator)
		}
		if err := validateAdvancedAuthTextValues(condition); err != nil {
			return err
		}
	case "query_parameter":
		if condition.Name == "" {
			return fmt.Errorf("query parameter name cannot be empty")
		}
		if !isAdvancedAuthTextOperator(condition.Operator, false) {
			return fmt.Errorf("unsupported Query operator %q", condition.Operator)
		}
		if err := validateAdvancedAuthTextValues(condition); err != nil {
			return err
		}
	case "http_method":
		if condition.Operator != "in" && condition.Operator != "not_in" {
			return fmt.Errorf("unsupported HTTP Method operator %q", condition.Operator)
		}
		if len(condition.Values) == 0 {
			return fmt.Errorf("HTTP Method condition requires at least one method")
		}
		seen := make(map[string]struct{}, len(condition.Values))
		methods := condition.Values[:0]
		for _, raw := range condition.Values {
			method := strings.ToUpper(strings.TrimSpace(raw))
			if method == "" {
				return fmt.Errorf("HTTP Method cannot be empty")
			}
			if _, exists := seen[method]; !exists {
				seen[method] = struct{}{}
				methods = append(methods, method)
			}
		}
		condition.Values = methods
	default:
		return fmt.Errorf("unsupported target %q", condition.Target)
	}
	return nil
}

func canonicalAdvancedAuthNetwork(value string, requireAddress bool) (string, error) {
	value = strings.TrimSpace(value)
	if requireAddress {
		address, err := netip.ParseAddr(value)
		if err == nil && address.Zone() == "" {
			address = address.Unmap()
			bits := 128
			if address.Is4() {
				bits = 32
			}
			return netip.PrefixFrom(address, bits).String(), nil
		}

		// Rust compiles exact-address rules into immutable host prefixes before
		// sending them over gRPC. Accept only /32 and /128 here; broader
		// networks remain invalid for equals/not_equals.
		prefix, prefixErr := netip.ParsePrefix(value)
		if prefixErr == nil && prefix.Addr().Zone() == "" &&
			prefix.Bits() == prefix.Addr().BitLen() {
			address = prefix.Addr().Unmap()
			return netip.PrefixFrom(address, address.BitLen()).String(), nil
		}
		return "", fmt.Errorf("must be a valid IPv4 or IPv6 address")
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "", fmt.Errorf("must be a valid IPv4 or IPv6 CIDR")
	}
	return prefix.Masked().String(), nil
}

func validAdvancedAuthHeaderName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" || strings.HasPrefix(lower, "x-reauth-") {
		return false
	}
	if strings.HasPrefix(lower, "x-forwarded-") || lower == "forwarded" ||
		lower == "x-real-ip" || lower == "ali-real-client-ip" || lower == "eo-connecting-ip" {
		return false
	}
	switch lower {
	case "host", "cookie", "authorization", "proxy-authorization", "connection",
		"keep-alive", "proxy-authenticate", "proxy-connection", "te", "trailer",
		"transfer-encoding", "upgrade":
		return false
	}
	for _, character := range lower {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') &&
			!strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			return false
		}
	}
	return true
}

func isAdvancedAuthTextOperator(operator string, pathTarget bool) bool {
	if slices.Contains([]string{"equals", "not_equals", "contains", "not_contains", "starts_with",
		"not_starts_with", "ends_with", "not_ends_with", "regex", "not_regex"}, operator) {
		return true
	}
	if pathTarget {
		return operator == "prefix" || operator == "not_prefix"
	}
	return operator == "exists" || operator == "not_exists"
}

func validateAdvancedAuthTextValues(condition *models.AdvancedAuthCondition) error {
	if condition.Operator == "exists" || condition.Operator == "not_exists" {
		condition.Values = nil
		return nil
	}
	if len(condition.Values) == 0 {
		return fmt.Errorf("operator %q requires a match value", condition.Operator)
	}
	for _, value := range condition.Values {
		if value == "" {
			return fmt.Errorf("operator %q does not allow empty match values", condition.Operator)
		}
		if (condition.Operator == "regex" || condition.Operator == "not_regex") && len(value) > advancedAuthMaxRegexBytes {
			return fmt.Errorf("regular expression exceeds %d bytes", advancedAuthMaxRegexBytes)
		}
		if condition.Operator == "regex" || condition.Operator == "not_regex" {
			if _, err := regexp.Compile("^(?:" + value + ")$"); err != nil {
				return fmt.Errorf("invalid RE2 regular expression")
			}
		}
	}
	return nil
}

func compileAdvancedAuthPolicy(config models.AdvancedAuthConfig) (*compiledAdvancedAuthPolicy, error) {
	return compileAdvancedAuthPolicyWithSets(config, nil)
}

func compileAdvancedAuthPolicyWithSets(
	config models.AdvancedAuthConfig,
	sets map[string]*compiledipset.Set,
) (*compiledAdvancedAuthPolicy, error) {
	normalized, err := normalizeAdvancedAuthConfig(config)
	if err != nil {
		return nil, err
	}
	if !normalized.Enabled {
		return nil, nil
	}
	policy := &compiledAdvancedAuthPolicy{
		enabled:            true,
		policyVersion:      normalized.PolicyVersion,
		idleTTLSeconds:     normalized.IdleTTLSeconds,
		maxLifetimeSeconds: normalized.MaxLifetimeSeconds,
		groups:             make([]compiledAdvancedAuthGroup, 0, len(normalized.Groups)),
	}
	for _, group := range normalized.Groups {
		compiledGroup := compiledAdvancedAuthGroup{
			id:         group.ID,
			conditions: make([]compiledAdvancedAuthCondition, 0, len(group.Conditions)),
		}
		for _, condition := range group.Conditions {
			compiled := compiledAdvancedAuthCondition{
				target:   condition.Target,
				operator: condition.Operator,
				name:     condition.Name,
				values:   append([]string(nil), condition.Values...),
			}
			if condition.Target == "http_method" {
				compiled.valueSet = make(map[string]struct{}, len(condition.Values))
				for _, method := range condition.Values {
					compiled.valueSet[method] = struct{}{}
				}
			}
			if condition.PolicyID != "" {
				set := sets[condition.PolicyID]
				if set == nil {
					return nil, fmt.Errorf(
						"advanced auth condition %q references missing IP set %q",
						condition.ID,
						condition.PolicyID,
					)
				}
				compiled.ipsets = append(compiled.ipsets, set)
			}
			if len(condition.CIDRs) > 0 {
				legacyPolicy, compileErr := compiledipset.Compile(condition.CIDRs)
				if compileErr != nil {
					return nil, fmt.Errorf("invalid advanced auth CIDR notation")
				}
				legacySet, decodeErr := compiledipset.Decode(legacyPolicy)
				if decodeErr != nil {
					return nil, decodeErr
				}
				compiled.ipsets = append(compiled.ipsets, legacySet)
			}
			if condition.Operator == "regex" || condition.Operator == "not_regex" {
				compiled.regexps = make([]*regexp.Regexp, 0, len(condition.Values))
				for _, expression := range condition.Values {
					compiledRegexp, compileErr := regexp.Compile("^(?:" + expression + ")$")
					if compileErr != nil {
						return nil, fmt.Errorf("compile advanced auth regular expression: %w", compileErr)
					}
					compiled.regexps = append(compiled.regexps, compiledRegexp)
				}
			}
			compiledGroup.conditions = append(compiledGroup.conditions, compiled)
		}
		policy.groups = append(policy.groups, compiledGroup)
	}
	return policy, nil
}

func (policy *compiledAdvancedAuthPolicy) evaluate(request *http.Request, clientIP string) *advancedAuthRuleMatch {
	if policy == nil || !policy.enabled || request == nil {
		return nil
	}
	address, _ := netip.ParseAddr(strings.TrimSpace(clientIP))
	for _, group := range policy.groups {
		matched := true
		for _, condition := range group.conditions {
			if !condition.matches(request, address) {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		return &advancedAuthRuleMatch{
			policyVersion: policy.policyVersion,
			groupID:       group.id,
		}
	}
	return nil
}

func advancedAuthIsUpgradeRequest(request *http.Request) bool {
	if request == nil {
		return false
	}
	connectionUpgrade := false
	for _, raw := range request.Header.Values("Connection") {
		for _, token := range strings.Split(raw, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				connectionUpgrade = true
				break
			}
		}
	}
	if !connectionUpgrade {
		return false
	}
	for _, raw := range request.Header.Values("Upgrade") {
		for _, token := range strings.Split(raw, ",") {
			// Matching Upgrade handshakes are forwarded to the auth bridge as
			// one-request grants. They must be identified even for protocols other
			// than WebSocket so Rust never relies on a 101 response to persist a
			// newly created browser credential.
			if strings.TrimSpace(token) != "" {
				return true
			}
		}
	}
	return false
}

func (condition compiledAdvancedAuthCondition) matches(request *http.Request, address netip.Addr) bool {
	switch condition.target {
	case "source_ip", "source_region":
		// A missing or malformed trusted client IP must never satisfy a
		// negative network condition (otherwise `not_in_cidr` becomes an
		// accidental allow-all rule).
		if !address.IsValid() {
			return false
		}
		matched := slices.ContainsFunc(condition.ipsets, func(set *compiledipset.Set) bool {
			return set != nil && set.Contains(address)
		})
		return matched != isAdvancedAuthNegativeOperator(condition.operator)
	case "url_path":
		return condition.matchesValues([]string{request.URL.Path}, true)
	case "request_header":
		values, exists := advancedAuthHeaderValues(request.Header, condition.name)
		return condition.matchesPresentValues(values, exists)
	case "query_parameter":
		values, exists := request.URL.Query()[condition.name]
		return condition.matchesPresentValues(values, exists)
	case "http_method":
		_, matched := condition.valueSet[strings.ToUpper(request.Method)]
		if condition.operator == "not_in" {
			return !matched
		}
		return matched
	default:
		return false
	}
}

// advancedAuthHeaderValues deliberately compares names case-insensitively.
// net/http canonicalizes parsed requests, but callers and tests can construct
// Header maps directly with lower-case keys; both forms must have identical
// rule semantics.
func advancedAuthHeaderValues(headers http.Header, name string) ([]string, bool) {
	if headers == nil {
		return nil, false
	}
	canonical := http.CanonicalHeaderKey(name)
	var all []string
	found := false
	for key, values := range headers {
		if strings.EqualFold(key, canonical) {
			found = true
			all = append(all, values...)
		}
	}
	return all, found
}

func (condition compiledAdvancedAuthCondition) matchesPresentValues(values []string, exists bool) bool {
	if condition.operator == "exists" {
		return exists
	}
	if condition.operator == "not_exists" {
		return !exists
	}
	if !exists {
		return false
	}
	return condition.matchesValues(values, true)
}

func (condition compiledAdvancedAuthCondition) matchesValues(values []string, exists bool) bool {
	if !exists {
		return false
	}
	negative := isAdvancedAuthNegativeOperator(condition.operator)
	positiveOperator := strings.TrimPrefix(condition.operator, "not_")
	if condition.operator == "not_equals" {
		positiveOperator = "equals"
	}
	if condition.operator == "not_contains" {
		positiveOperator = "contains"
	}
	if condition.operator == "not_prefix" {
		positiveOperator = "prefix"
	}
	if condition.operator == "not_regex" {
		positiveOperator = "regex"
	}
	anyMatched := false
	for _, candidate := range values {
		if condition.valueMatches(candidate, positiveOperator) {
			anyMatched = true
			break
		}
	}
	if negative {
		return !anyMatched
	}
	return anyMatched
}

func (condition compiledAdvancedAuthCondition) valueMatches(candidate string, operator string) bool {
	if operator == "regex" {
		for _, expression := range condition.regexps {
			if expression.MatchString(candidate) {
				return true
			}
		}
		return false
	}
	for _, expected := range condition.values {
		switch operator {
		case "equals":
			if candidate == expected {
				return true
			}
		case "contains":
			if strings.Contains(candidate, expected) {
				return true
			}
		case "starts_with", "prefix":
			if strings.HasPrefix(candidate, expected) {
				return true
			}
		case "ends_with":
			if strings.HasSuffix(candidate, expected) {
				return true
			}
		}
	}
	return false
}

func isAdvancedAuthNegativeOperator(operator string) bool {
	return strings.HasPrefix(operator, "not_")
}
