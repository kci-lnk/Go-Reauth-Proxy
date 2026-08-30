package staticserve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
)

func TestPathContainsCaseFoldedUsesComponentBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   bool
	}{
		{name: "same path different case", parent: "/private/etc", child: "/PRIVATE/ETC", want: true},
		{name: "descendant different case", parent: "/System", child: "/system/Library/Keys", want: true},
		{name: "component boundary", parent: "/private/etc", child: "/PRIVATE/ETC-backup", want: false},
		{name: "short child", parent: "/private/etc/keys", child: "/PRIVATE/ETC", want: false},
		{name: "unicode normalization", parent: "/srv/caf\u00e9", child: "/SRV/cafe\u0301/site", want: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := pathContainsCaseFolded(filepath.FromSlash(testCase.parent), filepath.FromSlash(testCase.child)); got != testCase.want {
				t.Fatalf("pathContainsCaseFolded(%q, %q) = %v, want %v", testCase.parent, testCase.child, got, testCase.want)
			}
		})
	}
}

func TestProtectedPathCannotBeBypassedWithPlatformCaseVariant(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("case-folded protected path policy is platform-specific")
	}
	protected := filepath.Join(t.TempDir(), "FnKnock", "Secrets")
	candidate := filepath.Join(filepath.Dir(filepath.Dir(protected)), "FNKNOCK", "SECRETS", "public")
	if err := ValidateProtectedPath(candidate, protected); !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("case-variant protected path error = %v, want ErrProtectedPath", err)
	}
}

func TestSafeWindowsFileNameRejectsDevicesAliasesAndADS(t *testing.T) {
	for _, name := range []string{
		"NUL", "nul.txt", "CON", "PRN.log", "AUX ", "COM1", "com9.txt", "LPT1", "LPT²",
		"CLOCK$", "clock$.txt", "CONIN$", "conout$", "file.txt:secret", "trailing.", "trailing ", "question?.txt", "pipe|name",
	} {
		if safeWindowsFileName(name) {
			t.Errorf("safeWindowsFileName(%q) = true, want false", name)
		}
	}
	for _, name := range []string{"index.html", "COM10", "LPT0", "console.txt", "résumé.md"} {
		if !safeWindowsFileName(name) {
			t.Errorf("safeWindowsFileName(%q) = false, want true", name)
		}
	}
}

func TestUnsafeWindowsPathNamespaceRejectsDeviceSpellings(t *testing.T) {
	for _, pathValue := range []string{
		`\\?\C:\Windows\System32`,
		`//?/C:/Windows/System32`,
		`\\.\GLOBALROOT\Device\HarddiskVolume1`,
		`//./pipe/fn-knock`,
		`\??\C:\Windows`,
	} {
		if !unsafeWindowsPathNamespace(pathValue) {
			t.Errorf("unsafeWindowsPathNamespace(%q) = false, want true", pathValue)
		}
	}
	for _, pathValue := range []string{
		`C:\Sites\docs`,
		`\\server\share\docs`,
	} {
		if unsafeWindowsPathNamespace(pathValue) {
			t.Errorf("unsafeWindowsPathNamespace(%q) = true, want false", pathValue)
		}
	}
}

func TestUnsafeWindowsStaticPathRejectsEveryUNCSpelling(t *testing.T) {
	for _, pathValue := range []string{
		`\\server\share\docs`,
		`//server/share/docs`,
		`\\localhost\C$\Windows\System32`,
		`\\127.0.0.1\C$\Windows`,
		`\\localhost\pipe\fn-knock`,
		`//localhost/mailslot/fn-knock`,
		`\\?\UNC\server\share\docs`,
		`\\.\pipe\fn-knock`,
		`\??\C:\Windows`,
	} {
		if !unsafeWindowsStaticPath(pathValue) {
			t.Errorf("unsafeWindowsStaticPath(%q) = false, want true", pathValue)
		}
	}
	for _, pathValue := range []string{
		`C:\Sites\docs`,
		`D:/public/assets`,
	} {
		if unsafeWindowsStaticPath(pathValue) {
			t.Errorf("unsafeWindowsStaticPath(%q) = true, want false", pathValue)
		}
	}
}

func TestNormalizeConfigRejectsNetworkStylePrefixesBeforePlatformCleaning(t *testing.T) {
	for _, pathValue := range []string{
		`//server/share/docs`,
		`\\server\share\docs`,
		`/\server/share/docs`,
		`\/server\share\docs`,
	} {
		_, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: pathValue})
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NormalizeConfig(%q) error = %v, want ErrInvalidConfig", pathValue, err)
		}
	}
}

func TestNormalizeConfigRejectsPOSIXBackslashInAnyPathComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backslash is a native separator on Windows")
	}
	pathValue := filepath.Join(t.TempDir(), "unsafe\\component", "public")
	_, err := NormalizeConfig(models.HostRuleTargetTypeDirectory, &models.StaticServeConfig{Path: pathValue})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NormalizeConfig(backslash ancestor) error = %v, want ErrInvalidConfig", err)
	}
}

func TestGatewayProtectedPathsIncludeUserCredentialRoots(t *testing.T) {
	userHome, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(userHome) == "" {
		t.Skipf("user home unavailable: %v", err)
	}
	protected := GatewayProtectedPaths("", "")
	wantSSH := filepath.Join(userHome, ".ssh")
	found := false
	for _, pathValue := range protected {
		if filepath.Clean(pathValue) == filepath.Clean(wantSSH) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("credential root %q missing from protected paths", wantSSH)
	}
	if err := ValidateProtectedPath(userHome, protected...); !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("serving the whole user home should overlap credential roots: %v", err)
	}
}

func TestOpenStaticDirectoryRootRechecksProtectedPathAfterPinning(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openStaticDirectoryRoot(rootPath, rootPath)
	if root != nil {
		_ = root.Close()
		t.Fatal("protected root unexpectedly opened")
	}
	if !errors.Is(err, ErrProtectedPath) {
		t.Fatalf("protected post-open check error = %v, want ErrProtectedPath", err)
	}
}

func TestConfiguredRootSymlinkCannotSelectProtectedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires elevated privileges on Windows")
	}
	workspace := t.TempDir()
	publicPath := filepath.Join(workspace, "public")
	protectedPath := filepath.Join(workspace, "protected")
	for _, directory := range []string{publicPath, protectedPath} {
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, filepath.Join(publicPath, "marker.txt"), "public")
	mustWriteFile(t, filepath.Join(protectedPath, "marker.txt"), "PROTECTED-SECRET")
	configuredPath := filepath.Join(workspace, "configured")
	if err := os.Symlink(publicPath, configuredPath); err != nil {
		t.Fatal(err)
	}

	cfg := &models.StaticServeConfig{Path: configuredPath}
	allowed := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/marker.txt", nil, Options{ProtectedPaths: []string{protectedPath}})
	if allowed.Code != http.StatusOK || allowed.Body.String() != "public" {
		t.Fatalf("safe root alias = %d %q", allowed.Code, allowed.Body.String())
	}
	if err := os.Remove(configuredPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protectedPath, configuredPath); err != nil {
		t.Fatal(err)
	}
	blocked := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/marker.txt", nil, Options{ProtectedPaths: []string{protectedPath}})
	if blocked.Code != http.StatusServiceUnavailable || strings.Contains(blocked.Body.String(), "PROTECTED-SECRET") {
		t.Fatalf("protected root alias = %d %q, want non-leaking 503", blocked.Code, blocked.Body.String())
	}
	probe := ProbePath(models.HostRuleTargetTypeDirectory, configuredPath, protectedPath)
	if probe.ErrorCode != ProbeErrorProtectedPath || probe.NormalizedPath != configuredPath {
		t.Fatalf("protected probe = %#v, want lexical path and protected_path", probe)
	}
}

func TestConfiguredRootSymlinkSwapNeverServesProtectedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation normally requires elevated privileges on Windows")
	}
	workspace := t.TempDir()
	publicPath := filepath.Join(workspace, "public")
	protectedPath := filepath.Join(workspace, "protected")
	for _, directory := range []string{publicPath, protectedPath} {
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, filepath.Join(publicPath, "marker.txt"), "public")
	const protectedMarker = "ROOT-SWAP-PROTECTED-SECRET"
	mustWriteFile(t, filepath.Join(protectedPath, "marker.txt"), protectedMarker)
	configuredPath := filepath.Join(workspace, "configured")
	if err := os.Symlink(publicPath, configuredPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ready sync.WaitGroup
	ready.Add(1)
	workerDone := make(chan error, 1)
	go func() {
		ready.Done()
		for iteration := 0; ; iteration++ {
			select {
			case <-ctx.Done():
				workerDone <- nil
				return
			default:
			}
			target := publicPath
			if iteration%2 == 1 {
				target = protectedPath
			}
			staging := filepath.Join(workspace, fmt.Sprintf(".configured-stage-%d", iteration%2))
			_ = os.Remove(staging)
			if err := os.Symlink(target, staging); err != nil {
				workerDone <- err
				return
			}
			if err := os.Rename(staging, configuredPath); err != nil {
				workerDone <- err
				return
			}
		}
	}()
	ready.Wait()

	cfg := &models.StaticServeConfig{Path: configuredPath}
	for iteration := 0; iteration < 750; iteration++ {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/marker.txt", nil, Options{ProtectedPaths: []string{protectedPath}})
		if strings.Contains(response.Body.String(), protectedMarker) {
			cancel()
			t.Fatalf("iteration %d served protected root: %d %q", iteration, response.Code, response.Body.String())
		}
		if response.Code != http.StatusOK && response.Code != http.StatusServiceUnavailable {
			cancel()
			t.Fatalf("iteration %d status = %d, want 200 or fail-closed 503", iteration, response.Code)
		}
	}
	cancel()
	select {
	case err := <-workerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("configured-root swap worker did not stop")
	}
}
