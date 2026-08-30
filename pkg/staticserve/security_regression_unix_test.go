//go:build !windows

package staticserve

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
	"golang.org/x/sys/unix"
)

func TestSecuritySpecialFilesAreNotListedOrServedWithoutBlocking(t *testing.T) {
	rootPath, err := os.MkdirTemp(os.TempDir(), "fnk-static-special-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootPath) })
	fifoPath := filepath.Join(rootPath, "named-pipe")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(rootPath, "s")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := openRootFileForRead(root, ".")
	if err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	_, _, _, err = scanDirectoryPageWithLimits(t.Context(), root, directory, ".", nil, 1, 10)
	_ = directory.Close()
	_ = root.Close()
	if !errors.Is(err, errDirectoryTooLarge) {
		t.Fatalf("special files bypassed raw scan limit: err=%v", err)
	}

	cfg := listingConfig(rootPath, false)
	listing := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/", nil, Options{})
	if listing.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", listing.Code, listing.Body.String())
	}
	if strings.Contains(listing.Body.String(), "named-pipe") || strings.Contains(listing.Body.String(), `href="s"`) {
		t.Fatalf("special file appeared in listing: %s", listing.Body.String())
	}

	socketResponse := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/s", nil, Options{})
	if socketResponse.Code != http.StatusNotFound {
		t.Errorf("socket response = %d %q, want 404", socketResponse.Code, socketResponse.Body.String())
	}

	done := make(chan *securityHTTPResult, 1)
	go func() {
		response := serveRequestNoTestingHelper(models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/named-pipe")
		done <- &securityHTTPResult{status: response.Code, body: response.Body.String()}
	}()
	select {
	case response := <-done:
		if response.status != http.StatusNotFound {
			t.Errorf("FIFO response = %d %q, want 404", response.status, response.body)
		}
	case <-time.After(250 * time.Millisecond):
		// Unblock an implementation that opened the FIFO without O_NONBLOCK so
		// the test process can terminate, but retain the timeout as a failure.
		fd, openErr := unix.Open(fifoPath, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if openErr == nil {
			_ = unix.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("serving a FIFO blocked the request; special files must be rejected without a blocking open")
	}

	// Ensure direct os.Open is not accidentally keeping the FIFO alive after
	// the request; this also catches descriptor leaks in repeated test runs.
	if file, err := os.OpenFile(fifoPath, os.O_RDONLY|unix.O_NONBLOCK, 0); err == nil {
		_ = file.Close()
	}
}

func TestSecuritySpecialMappingRootsAreRejectedWithoutBlocking(t *testing.T) {
	workspace, err := os.MkdirTemp(os.TempDir(), "fnk-static-special-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspace) })
	fifoPath := filepath.Join(workspace, "mapping-root")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	regularPath := filepath.Join(workspace, "regular-file")
	if err := os.WriteFile(regularPath, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		targetType string
		path       string
	}{
		{name: "directory root is FIFO", targetType: models.HostRuleTargetTypeDirectory, path: fifoPath},
		{name: "directory root is regular file", targetType: models.HostRuleTargetTypeDirectory, path: regularPath},
		{name: "file target is FIFO", targetType: models.HostRuleTargetTypeFile, path: fifoPath},
		{name: "file parent is FIFO", targetType: models.HostRuleTargetTypeFile, path: filepath.Join(fifoPath, "asset.txt")},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			done := make(chan *securityHTTPResult, 1)
			go func() {
				response := serveRequestNoTestingHelper(
					testCase.targetType,
					&models.StaticServeConfig{Path: testCase.path},
					http.MethodGet,
					"/",
				)
				done <- &securityHTTPResult{status: response.Code, body: response.Body.String()}
			}()
			select {
			case response := <-done:
				if response.status != http.StatusServiceUnavailable {
					t.Fatalf("response = %d %q, want 503", response.status, response.body)
				}
			case <-time.After(500 * time.Millisecond):
				// Permit a buggy blocking open to unwind so the test process itself
				// does not retain a goroutine after reporting the regression.
				fd, openErr := unix.Open(fifoPath, unix.O_WRONLY|unix.O_NONBLOCK, 0)
				if openErr == nil {
					_ = unix.Close(fd)
				}
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatal("special mapping root blocked the request")
			}
		})
	}
}

func TestSecurityConfiguredRootSwapToFIFOAfterPreopenNeverBlocks(t *testing.T) {
	workspace, err := os.MkdirTemp(os.TempDir(), "fnk-static-root-swap-fifo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspace) })
	rootPath := filepath.Join(workspace, "public")
	movedPath := filepath.Join(workspace, "public-pinned")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal(err)
	}

	type openResult struct {
		err         error
		mutationErr error
	}
	done := make(chan openResult, 1)
	go func() {
		var mutationErr error
		root, openErr := openStaticDirectoryRootAfterPreopen(rootPath, func() {
			if renameErr := os.Rename(rootPath, movedPath); renameErr != nil {
				mutationErr = renameErr
				return
			}
			mutationErr = unix.Mkfifo(rootPath, 0o600)
		})
		if root != nil {
			_ = root.Close()
		}
		done <- openResult{err: openErr, mutationErr: mutationErr}
	}()

	select {
	case result := <-done:
		if result.mutationErr != nil {
			t.Fatal(result.mutationErr)
		}
		if result.err == nil {
			t.Fatal("root swap unexpectedly opened a replaced pathname")
		}
	case <-time.After(500 * time.Millisecond):
		// An implementation that reopens rootPath is now blocked in O_RDONLY on
		// the FIFO. Connect a writer so it can unwind before failing the test.
		fd, openErr := unix.Open(rootPath, unix.O_WRONLY|unix.O_NONBLOCK, 0)
		if openErr == nil {
			_ = unix.Close(fd)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("os.Root construction reopened the swapped FIFO and blocked")
	}
}

type securityHTTPResult struct {
	status int
	body   string
}

func serveRequestNoTestingHelper(targetType string, cfg *models.StaticServeConfig, method, requestPath string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://static.example"+requestPath, nil)
	recorder := httptest.NewRecorder()
	Serve(recorder, request, targetType, cfg, Options{})
	return recorder
}
