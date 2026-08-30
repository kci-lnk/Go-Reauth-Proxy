package staticserve

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go-reauth-proxy/pkg/models"
)

// TestDockerReadOnlyMountHTTP is opt-in because its fixture must be mounted
// read-only by the container runtime. It verifies both the deployment contract
// and the actual static HTTP response on a native Linux filesystem.
func TestDockerReadOnlyMountHTTP(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("FN_KNOCK_STATIC_RO_SMOKE_ROOT"))
	if root == "" {
		t.Skip("FN_KNOCK_STATIC_RO_SMOKE_ROOT is not set")
	}

	writeProbe := filepath.Join(root, ".fn-knock-write-probe")
	if err := os.WriteFile(writeProbe, []byte("must fail"), 0o600); err == nil {
		_ = os.Remove(writeProbe)
		t.Fatal("static fixture is writable; bind it into the container with :ro")
	}

	response := serveRequest(
		t,
		models.HostRuleTargetTypeDirectory,
		&models.StaticServeConfig{Path: root},
		http.MethodGet,
		"/hello.txt",
		nil,
		Options{},
	)
	if response.Code != http.StatusOK || response.Body.String() != "hello from read-only mount\n" {
		t.Fatalf("read-only mount response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "public, max-age=0, must-revalidate" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("read-only mount headers = %#v", response.Header())
	}
}
