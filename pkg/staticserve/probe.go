package staticserve

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go-reauth-proxy/pkg/models"
)

const (
	ProbeErrorInvalidPath      = "invalid_path"
	ProbeErrorProtectedPath    = "protected_path"
	ProbeErrorNotFound         = "not_found"
	ProbeErrorPermissionDenied = "permission_denied"
	ProbeErrorTypeMismatch     = "type_mismatch"
	ProbeErrorUnsupportedType  = "unsupported_type"
	ProbeErrorUnavailable      = "unavailable"
)

type ProbeResult struct {
	RequestedType  string
	ActualType     string
	NormalizedPath string
	Exists         bool
	Readable       bool
	ErrorCode      string
}

// ProbePath performs an advisory check in the gateway process. Serve remains
// authoritative because files and mounts can change immediately after a probe.
func ProbePath(requestedType, pathValue string, protectedPaths ...string) ProbeResult {
	result := ProbeResult{RequestedType: models.NormalizeHostRuleTargetType(requestedType)}
	if result.RequestedType != models.HostRuleTargetTypeFile && result.RequestedType != models.HostRuleTargetTypeDirectory {
		result.ErrorCode = ProbeErrorUnsupportedType
		return result
	}

	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" || !filepath.IsAbs(pathValue) {
		result.ErrorCode = ProbeErrorInvalidPath
		return result
	}
	result.NormalizedPath = filepath.Clean(pathValue)
	if _, err := NormalizeConfig(result.RequestedType, &models.StaticServeConfig{Path: result.NormalizedPath}, protectedPaths...); err != nil {
		if errors.Is(err, ErrProtectedPath) {
			result.ErrorCode = ProbeErrorProtectedPath
		} else {
			result.ErrorCode = ProbeErrorInvalidPath
		}
		return result
	}
	resolvedPath, err := resolveConfiguredStaticPath(result.NormalizedPath, protectedPaths...)
	if err != nil {
		if errors.Is(err, ErrProtectedPath) {
			result.ErrorCode = ProbeErrorProtectedPath
		} else {
			result.ErrorCode = classifyProbeError(err)
		}
		return result
	}

	info, err := os.Stat(resolvedPath)
	if err != nil {
		result.ErrorCode = classifyProbeError(err)
		return result
	}
	result.Exists = true
	switch {
	case info.Mode().IsRegular():
		result.ActualType = models.HostRuleTargetTypeFile
	case info.IsDir():
		result.ActualType = models.HostRuleTargetTypeDirectory
	default:
		result.ErrorCode = ProbeErrorUnsupportedType
		return result
	}
	if result.ActualType != result.RequestedType {
		result.ErrorCode = ProbeErrorTypeMismatch
		return result
	}

	if result.RequestedType == models.HostRuleTargetTypeFile {
		result.Readable, result.ErrorCode = probeFileReadable(resolvedPath, protectedPaths...)
	} else {
		result.Readable, result.ErrorCode = probeDirectoryReadable(resolvedPath, protectedPaths...)
	}
	return result
}

func probeFileReadable(pathValue string, protectedPaths ...string) (bool, string) {
	root, err := openStaticDirectoryRoot(filepath.Dir(pathValue), protectedPaths...)
	if err != nil {
		return false, classifyProbeError(err)
	}
	defer root.Close()
	file, err := openRootFileForRead(root, filepath.Base(pathValue))
	if err != nil {
		return false, classifyProbeError(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, classifyProbeError(err)
	}
	if !info.Mode().IsRegular() {
		return false, ProbeErrorUnsupportedType
	}
	return true, ""
}

func probeDirectoryReadable(pathValue string, protectedPaths ...string) (bool, string) {
	root, err := openStaticDirectoryRoot(pathValue, protectedPaths...)
	if err != nil {
		return false, classifyProbeError(err)
	}
	defer root.Close()
	directory, err := openRootFileForRead(root, ".")
	if err != nil {
		return false, classifyProbeError(err)
	}
	defer directory.Close()
	_, err = directory.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, classifyProbeError(err)
	}
	return true, ""
}

func classifyProbeError(err error) string {
	switch {
	case errors.Is(err, ErrInvalidConfig):
		return ProbeErrorInvalidPath
	case errors.Is(err, ErrProtectedPath):
		return ProbeErrorProtectedPath
	case errors.Is(err, os.ErrNotExist):
		return ProbeErrorNotFound
	case errors.Is(err, os.ErrPermission):
		return ProbeErrorPermissionDenied
	default:
		return ProbeErrorUnavailable
	}
}
