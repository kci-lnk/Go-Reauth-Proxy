package waf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"

	"go-reauth-proxy/pkg/models"
)

const (
	localRuleSetID             = "local"
	internalSetupRuleID        = 1000000
	initializationRuleFilename = "REQUEST-901-INITIALIZATION.conf"
	crsSetupVersion            = 4250
	rulesStateFilename         = "rules-state.json"
	systemRulesDirName         = "system"
	customRulesDirName         = "custom"
	maxRulesStateBytes         = 1 << 20
	maxRuleFileBytes           = 16 << 20
)

var (
	defaultDisabledSystemRuleFilenames = map[string]struct{}{
		"REQUEST-920-PROTOCOL-ENFORCEMENT.conf":    {},
		"REQUEST-930-APPLICATION-ATTACK-LFI.conf":  {},
		"REQUEST-932-APPLICATION-ATTACK-RCE.conf":  {},
		"REQUEST-941-APPLICATION-ATTACK-XSS.conf":  {},
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf": {},
	}
)

const secRuleUpdateTargetByIDDirective = "SecRuleUpdateTargetById"

type CompiledRuntime struct {
	Config     models.WAFConfig
	BundleID   string
	BundlePath string
	BundleHash string
	LoadedAt   time.Time
	WAF        coraza.WAF
}

type rulesState struct {
	SystemEnabled map[string]bool `json:"system_enabled"`
	CustomEnabled map[string]bool `json:"custom_enabled"`
}

func buildCompiledRuntime(cfg models.WAFConfig, defaultRulesDir string, bundleID string, bundlePath string) (*CompiledRuntime, error) {
	cfg = NormalizeConfig(cfg, defaultRulesDir)
	rulesDir, err := resolveRulesDir(cfg.RulesDir)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(bundlePath) != "" {
		return nil, fmt.Errorf("bundle_path is no longer supported; WAF loads rules_dir directly")
	}
	if err := ensureRulesDirectories(rulesDir); err != nil {
		return nil, err
	}
	state, err := readRulesState(rulesDir)
	if err != nil {
		return nil, err
	}
	targets := loadOrder(rulesDir, state)
	ruleSetHash, err := hashRuleSet(rulesDir, targets)
	if err != nil {
		return nil, err
	}
	definedRuleIDs, err := collectDefinedRuleIDs(targets)
	if err != nil {
		return nil, err
	}

	wafConfig := coraza.NewWAFConfig().
		WithRootFS(updateTargetFilteringFS{
			root:           os.DirFS(rulesDir),
			definedRuleIDs: definedRuleIDs,
		}).
		WithRequestBodyLimit(cfg.RequestBodyLimitBytes).
		WithRequestBodyInMemoryLimit(cfg.RequestBodyInMemoryLimitBytes).
		WithDirectives(dynamicDirectives(cfg))
	if cfg.RequestBodyAccess {
		wafConfig = wafConfig.WithRequestBodyAccess()
	}
	if cfg.ResponseBodyAccess {
		wafConfig = wafConfig.WithResponseBodyAccess()
	}

	for _, file := range targets {
		if file.path == "" {
			continue
		}
		rel, err := filepath.Rel(rulesDir, file.path)
		if err != nil {
			return nil, err
		}
		wafConfig = wafConfig.WithDirectivesFromFile(filepath.ToSlash(rel))
	}

	compiledWAF, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, err
	}
	cfg.ActiveBundleID = localRuleSetID
	return &CompiledRuntime{
		Config:     cfg,
		BundleID:   localRuleSetID,
		BundlePath: rulesDir,
		BundleHash: ruleSetHash,
		LoadedAt:   time.Now().UTC(),
		WAF:        compiledWAF,
	}, nil
}

type loadKind int

const (
	loadFile loadKind = iota
)

type loadTarget struct {
	kind loadKind
	path string
}

func loadOrder(rulesDir string, state rulesState) []loadTarget {
	targets := globEnabledTargets(filepath.Join(rulesDir, systemRulesDirName), state.SystemEnabled, isSystemRuleEnabledByDefault)
	targets = append(targets, globEnabledTargets(filepath.Join(rulesDir, customRulesDirName), state.CustomEnabled, func(string) bool {
		return true
	})...)
	return targets
}

func globEnabledTargets(dir string, enabled map[string]bool, enabledByDefault func(string) bool) []loadTarget {
	matches, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	sort.Strings(matches)
	targets := make([]loadTarget, 0, len(matches))
	for _, match := range matches {
		filename := filepath.Base(match)
		if filename == initializationRuleFilename {
			targets = append(targets, loadTarget{kind: loadFile, path: match})
			continue
		}
		if value, ok := enabled[filename]; ok {
			if !value {
				continue
			}
		} else if enabledByDefault != nil && !enabledByDefault(filename) {
			continue
		}
		targets = append(targets, loadTarget{kind: loadFile, path: match})
	}
	return targets
}

func isSystemRuleEnabledByDefault(filename string) bool {
	if filename == initializationRuleFilename {
		return true
	}
	_, disabled := defaultDisabledSystemRuleFilenames[filename]
	return !disabled
}

func dynamicDirectives(cfg models.WAFConfig) string {
	engine := "DetectionOnly"
	switch cfg.Mode {
	case ModeBlocking:
		engine = "On"
	case ModeOff:
		engine = "Off"
	}
	requestBodyAccess := "Off"
	if cfg.RequestBodyAccess {
		requestBodyAccess = "On"
	}
	responseBodyAccess := "Off"
	if cfg.ResponseBodyAccess {
		responseBodyAccess = "On"
	}

	return fmt.Sprintf(`
SecRuleEngine %s
SecRequestBodyAccess %s
SecRequestBodyLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction ProcessPartial
SecResponseBodyAccess %s
SecAction "id:%d,phase:1,pass,nolog,t:none,setvar:tx.crs_setup_version=%d,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.paranoia_level=%d,setvar:tx.executing_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d"
`,
		engine,
		requestBodyAccess,
		cfg.RequestBodyLimitBytes,
		cfg.RequestBodyInMemoryLimitBytes,
		responseBodyAccess,
		internalSetupRuleID,
		crsSetupVersion,
		cfg.ParanoiaLevel,
		cfg.ExecutingParanoiaLevel,
		cfg.ParanoiaLevel,
		cfg.ExecutingParanoiaLevel,
		cfg.InboundAnomalyThreshold,
		cfg.OutboundAnomalyThreshold,
	)
}

func resolveRulesDir(rulesDir string) (string, error) {
	rulesDir = strings.TrimSpace(rulesDir)
	if rulesDir == "" {
		return "", fmt.Errorf("rules_dir is required")
	}
	return filepath.Abs(filepath.Clean(rulesDir))
}

func ensureRulesDirectories(root string) error {
	if err := os.MkdirAll(filepath.Join(root, systemRulesDirName), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, customRulesDirName), 0o755); err != nil {
		return err
	}
	return requireDirectory(root)
}

func ensureWithin(root string, target string) error {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return fmt.Errorf("path escapes rules_dir")
	}
	return nil
}

func requireDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	return nil
}

func readRulesState(rulesDir string) (rulesState, error) {
	state := rulesState{
		SystemEnabled: map[string]bool{},
		CustomEnabled: map[string]bool{},
	}
	statePath := filepath.Join(rulesDir, rulesStateFilename)
	raw, err := readFileLimited(statePath, maxRulesStateBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, err
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if state.SystemEnabled == nil {
		state.SystemEnabled = map[string]bool{}
	}
	if state.CustomEnabled == nil {
		state.CustomEnabled = map[string]bool{}
	}
	return state, nil
}

func collectDefinedRuleIDs(targets []loadTarget) (map[int]struct{}, error) {
	ids := map[int]struct{}{}
	for _, target := range targets {
		if target.path == "" || !strings.EqualFold(filepath.Ext(target.path), ".conf") {
			continue
		}
		raw, err := readFileLimited(target.path, maxRuleFileBytes)
		if err != nil {
			return nil, err
		}
		for start := 0; start < len(raw); {
			end := bytes.IndexByte(raw[start:], '\n')
			lineEnd := len(raw)
			if end >= 0 {
				lineEnd = start + end
			}
			line := bytes.TrimSpace(raw[start:lineEnd])
			if len(line) == 0 || line[0] == '#' {
				if end < 0 {
					break
				}
				start = lineEnd + 1
				continue
			}
			collectRuleIDActionIDs(line, ids)
			if end < 0 {
				break
			}
			start = lineEnd + 1
		}
	}
	return ids, nil
}

type updateTargetFilteringFS struct {
	root           fs.FS
	definedRuleIDs map[int]struct{}
}

func (f updateTargetFilteringFS) Open(name string) (fs.File, error) {
	// Coraza normalizes directive paths with filepath semantics. On Windows that
	// can produce backslashes, while io/fs requires slash-separated valid paths.
	name = filepath.ToSlash(name)
	if !strings.EqualFold(filepath.Ext(name), ".conf") {
		return f.root.Open(name)
	}

	file, err := f.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	raw, err := readLimited(file, maxRuleFileBytes, name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	filtered, changed := filterMissingUpdateTargetDirectives(raw, f.definedRuleIDs)
	if !changed {
		return f.root.Open(name)
	}
	return &filteredRuleFile{
		Reader: bytes.NewReader(filtered),
		info: filteredRuleFileInfo{
			name:    info.Name(),
			size:    int64(len(filtered)),
			mode:    info.Mode(),
			modTime: info.ModTime(),
			sys:     info.Sys(),
		},
	}, nil
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLimited(file, maxBytes, path)
}

func readLimited(reader io.Reader, maxBytes int64, name string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%s exceeds maximum size of %d bytes", name, maxBytes)
	}
	return raw, nil
}

func filterMissingUpdateTargetDirectives(raw []byte, definedRuleIDs map[int]struct{}) ([]byte, bool) {
	changed := false
	copyStart := 0
	var out []byte
	for start := 0; start < len(raw); {
		end := bytes.IndexByte(raw[start:], '\n')
		next := len(raw)
		if end >= 0 {
			next = start + end + 1
		}
		line := raw[start:next]
		missingID, skip := missingUpdateTargetRuleID(line, definedRuleIDs)
		if skip {
			if !changed {
				changed = true
				out = make([]byte, 0, len(raw))
				out = append(out, raw[:start]...)
			} else {
				out = append(out, raw[copyStart:start]...)
			}
			out = append(out, "# fn-knock skipped SecRuleUpdateTargetById "...)
			out = append(out, missingID...)
			out = append(out, " because the target rule is not enabled"...)
			if len(line) > 0 && line[len(line)-1] == '\n' {
				out = append(out, '\n')
			}
			copyStart = next
		}
		start = next
	}
	if !changed {
		return raw, false
	}
	out = append(out, raw[copyStart:]...)
	return out, true
}

func missingUpdateTargetRuleID(line []byte, definedRuleIDs map[int]struct{}) ([]byte, bool) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 || trimmed[0] == '#' {
		return nil, false
	}
	digits, ok := parseSecRuleUpdateTargetByID(trimmed)
	if !ok {
		return nil, false
	}
	id, ok := parseRuleIDDigits(digits)
	if !ok {
		return nil, false
	}
	_, defined := definedRuleIDs[id]
	return digits, !defined
}

func collectRuleIDActionIDs(line []byte, ids map[int]struct{}) {
	for i := 0; i+1 < len(line); i++ {
		if lowerASCII(line[i]) != 'i' || lowerASCII(line[i+1]) != 'd' {
			continue
		}
		if i > 0 && isRegexpWordByte(line[i-1]) {
			continue
		}
		j := i + 2
		for j < len(line) && isRegexpSpace(line[j]) {
			j++
		}
		if j >= len(line) || line[j] != ':' {
			continue
		}
		j++
		for j < len(line) && isRegexpSpace(line[j]) {
			j++
		}
		start := j
		for j < len(line) && isASCIIDigit(line[j]) {
			j++
		}
		if start == j {
			continue
		}
		if j < len(line) && isRegexpWordByte(line[j]) {
			continue
		}
		if id, ok := parseRuleIDDigits(line[start:j]); ok {
			ids[id] = struct{}{}
		}
		i = j
	}
}

func parseSecRuleUpdateTargetByID(line []byte) ([]byte, bool) {
	if !equalFoldASCIIPrefixBytes(line, secRuleUpdateTargetByIDDirective) {
		return nil, false
	}
	i := len(secRuleUpdateTargetByIDDirective)
	if i >= len(line) || !isRegexpSpace(line[i]) {
		return nil, false
	}
	for i < len(line) && isRegexpSpace(line[i]) {
		i++
	}
	start := i
	for i < len(line) && isASCIIDigit(line[i]) {
		i++
	}
	if start == i {
		return nil, false
	}
	if i < len(line) && isRegexpWordByte(line[i]) {
		return nil, false
	}
	return line[start:i], true
}

func parseRuleIDDigits(raw []byte) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	maxInt := int(^uint(0) >> 1)
	id := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
		digit := int(c - '0')
		if id > (maxInt-digit)/10 {
			return 0, false
		}
		id = id*10 + digit
	}
	return id, true
}

func equalFoldASCIIPrefixBytes(value []byte, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lowerASCII(value[i]) != lowerASCII(prefix[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isRegexpSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\f', '\r':
		return true
	default:
		return false
	}
}

func isRegexpWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}

type filteredRuleFile struct {
	*bytes.Reader
	info filteredRuleFileInfo
}

func (f *filteredRuleFile) Stat() (fs.FileInfo, error) {
	return f.info, nil
}

func (f *filteredRuleFile) Close() error {
	return nil
}

type filteredRuleFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	sys     any
}

func (i filteredRuleFileInfo) Name() string {
	return i.name
}

func (i filteredRuleFileInfo) Size() int64 {
	return i.size
}

func (i filteredRuleFileInfo) Mode() fs.FileMode {
	return i.mode
}

func (i filteredRuleFileInfo) ModTime() time.Time {
	return i.modTime
}

func (i filteredRuleFileInfo) IsDir() bool {
	return false
}

func (i filteredRuleFileInfo) Sys() any {
	return i.sys
}

func hashRuleSet(rulesDir string, targets []loadTarget) (string, error) {
	h := sha256.New()
	for _, target := range targets {
		if err := ensureWithin(rulesDir, target.path); err != nil {
			return "", err
		}
		rel, err := filepath.Rel(rulesDir, target.path)
		if err != nil {
			return "", err
		}
		rel = filepath.ToSlash(rel)
		_, _ = h.Write([]byte(rel))
		_, _ = h.Write([]byte{0})
		f, err := os.Open(target.path)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
