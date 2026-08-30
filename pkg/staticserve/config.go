package staticserve

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"go-reauth-proxy/pkg/models"
	"golang.org/x/text/unicode/norm"
)

const (
	DefaultPageSize            = 100
	MaxDirectoryVisibleEntries = 1_000_000
	MaxDirectoryScannedEntries = 1_000_000
	MaxReadmeBytes             = 1 << 20
	MaxIndexFiles              = 16
)

// DefaultIndexFiles is the default materialized by the control plane when a
// directory mapping omits index_files. The data plane must not apply it to an
// empty slice: proto3 repeated fields cannot distinguish omitted from an
// explicitly empty list, and an empty list intentionally disables index lookup.
var DefaultIndexFiles = []string{"index.html", "index.htm"}

var (
	ErrInvalidConfig = errors.New("invalid static serve configuration")
	ErrProtectedPath = errors.New("static serve path overlaps a protected directory")
)

// GatewayProtectedPaths returns local data roots that must never be exposed by
// a static mapping. Callers provide the config runtime directory and the
// optional FN_KNOCK_DATA_DIR value from their own process context.
func GatewayProtectedPaths(runtimeDir, dataDir string) []string {
	paths := make([]string, 0, 16)
	if strings.TrimSpace(runtimeDir) != "" {
		paths = append(paths, runtimeDir)
	}
	if strings.TrimSpace(dataDir) != "" {
		paths = append(paths, dataDir)
	}
	for _, name := range []string{
		"FN_KNOCK_GATEWAY_CONFIG_DIR",
		"FN_KNOCK_GATEWAY_LOGS_DIR",
		"FN_KNOCK_GATEWAY_WAF_DIR",
		"FN_KNOCK_DIAGNOSTIC_LOG_DIR",
		"GO_REPROXY_DEBUG_LOG_DIR",
	} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			paths = append(paths, value)
		}
	}
	if userHome, err := os.UserHomeDir(); err == nil && strings.TrimSpace(userHome) != "" {
		for _, relative := range []string{
			".ssh", ".gnupg", ".aws", ".kube",
			filepath.Join(".config", "fn-knock"),
			filepath.Join(".local", "share", "fn-knock"),
		} {
			paths = append(paths, filepath.Join(userHome, relative))
		}
	}
	if runtime.GOOS == "windows" {
		for _, name := range []string{
			"SystemRoot", "WINDIR", "ProgramData", "ProgramFiles", "ProgramFiles(x86)",
			"ProgramW6432", "APPDATA", "LOCALAPPDATA",
		} {
			if value := strings.TrimSpace(os.Getenv(name)); value != "" {
				paths = append(paths, value)
			}
		}
	} else {
		paths = append(paths,
			"/proc", "/sys", "/dev", "/run", "/etc", "/boot", "/root",
			"/bin", "/sbin", "/usr", "/lib", "/lib64",
			"/var/lib", "/var/log", "/var/run", "/var/spool",
		)
		if runtime.GOOS == "darwin" {
			paths = append(paths,
				"/System", "/Library/Keychains", "/private/etc", "/private/var/db",
				"/private/var/root", "/private/var/run",
			)
		}
	}
	return paths
}

// NormalizeConfig validates the durable/static parts of a mapping without
// requiring the path to exist. Runtime opens remain authoritative because a
// mount may legitimately disappear and later return.
func NormalizeConfig(targetType string, cfg *models.StaticServeConfig, protectedPaths ...string) (*models.StaticServeConfig, error) {
	targetType = models.NormalizeHostRuleTargetType(targetType)
	if targetType != models.HostRuleTargetTypeFile && targetType != models.HostRuleTargetTypeDirectory {
		return nil, fmt.Errorf("%w: target type must be file or directory", ErrInvalidConfig)
	}
	if cfg == nil {
		return nil, fmt.Errorf("%w: static_serve is required", ErrInvalidConfig)
	}

	pathValue := strings.TrimSpace(cfg.Path)
	if pathValue == "" {
		return nil, fmt.Errorf("%w: path is required", ErrInvalidConfig)
	}
	if strings.IndexByte(pathValue, 0) >= 0 || !utf8.ValidString(pathValue) {
		return nil, fmt.Errorf("%w: path is not valid UTF-8", ErrInvalidConfig)
	}
	if windowsUNCPath(pathValue) {
		return nil, fmt.Errorf("%w: network paths are not allowed", ErrInvalidConfig)
	}
	if runtime.GOOS != "windows" && strings.Contains(pathValue, "\\") {
		return nil, fmt.Errorf("%w: backslash is not allowed in a POSIX path", ErrInvalidConfig)
	}
	if runtime.GOOS == "windows" && unsafeWindowsStaticPath(pathValue) {
		return nil, fmt.Errorf("%w: Windows device namespaces and UNC paths are not allowed", ErrInvalidConfig)
	}
	if !filepath.IsAbs(pathValue) {
		return nil, fmt.Errorf("%w: path must be absolute", ErrInvalidConfig)
	}
	pathValue = filepath.Clean(pathValue)
	if filepath.Dir(pathValue) == pathValue {
		return nil, fmt.Errorf("%w: filesystem roots cannot be served", ErrInvalidConfig)
	}
	if err := ValidateProtectedPath(pathValue, protectedPaths...); err != nil {
		return nil, err
	}

	normalized := &models.StaticServeConfig{
		Path: pathValue,
		DirectoryListing: models.StaticDirectoryListingConfig{
			Enabled:      cfg.DirectoryListing.Enabled,
			RenderReadme: cfg.DirectoryListing.RenderReadme,
		},
	}

	if targetType == models.HostRuleTargetTypeFile {
		if len(cfg.IndexFiles) != 0 || cfg.DirectoryListing.Enabled || cfg.DirectoryListing.RenderReadme {
			return nil, fmt.Errorf("%w: directory options are not valid for a file mapping", ErrInvalidConfig)
		}
		base := filepath.Base(pathValue)
		if base == "." || base == string(filepath.Separator) || !safeVisibleName(base) {
			return nil, fmt.Errorf("%w: file path must name a visible file", ErrInvalidConfig)
		}
		return normalized, nil
	}

	if cfg.DirectoryListing.RenderReadme && !cfg.DirectoryListing.Enabled {
		return nil, fmt.Errorf("%w: README rendering requires directory listing", ErrInvalidConfig)
	}
	if !safeVisibleName(filepath.Base(pathValue)) {
		return nil, fmt.Errorf("%w: directory path must name a visible directory", ErrInvalidConfig)
	}
	indexFiles := cfg.IndexFiles
	if len(indexFiles) > MaxIndexFiles {
		return nil, fmt.Errorf("%w: too many index files", ErrInvalidConfig)
	}
	normalized.IndexFiles = make([]string, 0, len(indexFiles))
	seen := make(map[string]struct{}, len(indexFiles))
	for _, value := range indexFiles {
		name := strings.TrimSpace(value)
		if !validIndexFileName(name) {
			return nil, fmt.Errorf("%w: invalid index file name %q", ErrInvalidConfig, value)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		normalized.IndexFiles = append(normalized.IndexFiles, name)
	}
	return normalized, nil
}

// resolveConfiguredStaticPath resolves only for the current data-plane open.
// The lexical path remains the durable/API value so real filesystem topology
// is never disclosed. Opening the resolved spelling prevents a configured root
// symlink from being switched to a protected tree between validation and
// os.OpenRoot; openRootFileForRead performs an identity check after the open as
// a second race boundary.
func resolveConfiguredStaticPath(pathValue string, protectedPaths ...string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Clean(pathValue))
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if windowsUNCPath(resolved) || (runtime.GOOS == "windows" && unsafeWindowsStaticPath(resolved)) {
		return "", ErrInvalidConfig
	}
	if !filepath.IsAbs(resolved) || filepath.Dir(resolved) == resolved {
		return "", ErrInvalidConfig
	}
	if !safeVisibleName(filepath.Base(resolved)) {
		return "", ErrInvalidConfig
	}
	if err := ValidateProtectedPath(resolved, protectedPaths...); err != nil {
		return "", err
	}
	return resolved, nil
}

func validIndexFileName(name string) bool {
	return name != "" && len(name) <= 255 && utf8.RuneCountInString(name) <= 255 && filepath.Base(name) == name && safeVisibleName(name)
}

func safeVisibleName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return false
	}
	if !utf8.ValidString(name) || strings.ContainsAny(name, "/\\\x00") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	if runtime.GOOS == "windows" && !safeWindowsFileName(name) {
		return false
	}
	return true
}

// safeWindowsFileName is intentionally stricter than CreateFile. Besides
// blocking NTFS alternate data streams, it rejects names Win32 normalizes to a
// device or another spelling. os.Root applies its own reserved-name checks;
// keeping this lexical guard makes validation, listing, and serving agree.
func safeWindowsFileName(name string) bool {
	if strings.ContainsAny(name, `<>:"|?*`) || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	base := name
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	base = strings.TrimRight(base, " ")
	upper := strings.ToUpper(base)
	switch upper {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9' {
		return false
	}
	if strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(upper, "COM"), "LPT")
		if suffix == "¹" || suffix == "²" || suffix == "³" {
			return false
		}
	}
	return true
}

// unsafeWindowsPathNamespace rejects Win32/NT device spellings before any
// lexical normalization. Extended-length paths can otherwise give the same
// protected directory a different volume spelling (for example \\?\C:\\Windows)
// and are unnecessary for an administrator-selected static root.
func unsafeWindowsPathNamespace(pathValue string) bool {
	value := strings.ReplaceAll(strings.TrimSpace(pathValue), "/", "\\")
	upper := strings.ToUpper(value)
	return strings.HasPrefix(upper, `\\?\`) ||
		strings.HasPrefix(upper, `\\.\`) ||
		strings.HasPrefix(upper, `\??\`)
}

// unsafeWindowsStaticPath is kept independent of runtime.GOOS so its complete
// lexical policy can be tested on non-Windows builders. V1 accepts only local
// drive-absolute paths on Windows: every UNC spelling is rejected before any
// EvalSymlinks, Stat, or open. Besides preventing protected-directory aliases
// such as \\localhost\C$, this keeps named-pipe and mailslot UNC paths away from
// potentially blocking filesystem calls.
func unsafeWindowsStaticPath(pathValue string) bool {
	return unsafeWindowsPathNamespace(pathValue) || windowsUNCPath(pathValue)
}

func windowsUNCPath(pathValue string) bool {
	value := strings.ReplaceAll(strings.TrimSpace(pathValue), "/", "\\")
	return strings.HasPrefix(value, `\\`)
}

// ValidateProtectedPath rejects both descendants and ancestors of protected
// directories. Rejecting ancestors prevents a broad mapping from indirectly
// exposing the gateway's runtime data as a nested child.
func ValidateProtectedPath(candidate string, protectedPaths ...string) error {
	candidatePaths := comparablePaths(candidate)
	for _, protected := range protectedPaths {
		protected = strings.TrimSpace(protected)
		if protected == "" {
			continue
		}
		for _, candidatePath := range candidatePaths {
			for _, protectedPath := range comparablePaths(protected) {
				if pathsOverlap(candidatePath, protectedPath) {
					return ErrProtectedPath
				}
			}
		}
	}
	return nil
}

func comparablePaths(value string) []string {
	if !filepath.IsAbs(value) {
		if absolute, err := filepath.Abs(value); err == nil {
			value = absolute
		}
	}
	value = filepath.Clean(value)
	paths := []string{value}
	if resolved, err := filepath.EvalSymlinks(value); err == nil {
		resolved = filepath.Clean(resolved)
		if resolved != value {
			paths = append(paths, resolved)
		}
	}
	return paths
}

func pathsOverlap(first, second string) bool {
	first, second = filepath.Clean(first), filepath.Clean(second)
	return pathContains(first, second) || pathContains(second, first)
}

func pathContains(parent, child string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return pathContainsCaseFolded(parent, child)
	}
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}

// macOS and Windows commonly use case-insensitive filesystems even though
// filepath.Rel compares strings case-sensitively. Compare complete path
// components so a spelling such as /PRIVATE/ETC cannot bypass a protected
// /private/etc prefix. NFC normalization also closes the equivalent Unicode
// spelling used by normalization-insensitive APFS volumes. Conservatively
// treating a case-sensitive volume the same way can only reject a mapping.
func pathContainsCaseFolded(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	parentVolume, childVolume := filepath.VolumeName(parent), filepath.VolumeName(child)
	if !equalFoldPathComponent(parentVolume, childVolume) || filepath.IsAbs(parent) != filepath.IsAbs(child) {
		return false
	}
	parentParts := splitPathComponents(strings.TrimPrefix(parent, parentVolume))
	childParts := splitPathComponents(strings.TrimPrefix(child, childVolume))
	if len(parentParts) > len(childParts) {
		return false
	}
	for index := range parentParts {
		if !equalFoldPathComponent(parentParts[index], childParts[index]) {
			return false
		}
	}
	return true
}

func splitPathComponents(value string) []string {
	return strings.FieldsFunc(value, func(character rune) bool {
		return character == '/' || character == '\\'
	})
}

func equalFoldPathComponent(first, second string) bool {
	return strings.EqualFold(norm.NFC.String(first), norm.NFC.String(second))
}
