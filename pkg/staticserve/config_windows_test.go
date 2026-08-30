//go:build windows

package staticserve

import (
	"errors"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestNormalizeConfigRejectsUNCBeforeFilesystemAccess(t *testing.T) {
	paths := []string{
		`\\server\share\docs`,
		`//server/share/docs`,
		`\\localhost\C$\Windows\System32`,
		`\\127.0.0.1\C$\Windows`,
		`\\localhost\pipe\fn-knock`,
		`\\localhost\mailslot\fn-knock`,
		`\\?\UNC\server\share\docs`,
		`\\.\pipe\fn-knock`,
	}
	for _, targetType := range []string{models.HostRuleTargetTypeFile, models.HostRuleTargetTypeDirectory} {
		for _, pathValue := range paths {
			t.Run(targetType+"/"+pathValue, func(t *testing.T) {
				_, err := NormalizeConfig(targetType, &models.StaticServeConfig{Path: pathValue})
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("NormalizeConfig(%q) error = %v, want ErrInvalidConfig", pathValue, err)
				}
				probe := ProbePath(targetType, pathValue)
				if probe.ErrorCode != ProbeErrorInvalidPath {
					t.Fatalf("ProbePath(%q) = %#v, want invalid_path", pathValue, probe)
				}
			})
		}
	}
}

func TestNormalizeConfigAndProbeRejectWindowsTrailingSpace(t *testing.T) {
	pathValue := `C:\parent\child `
	for _, targetType := range []string{models.HostRuleTargetTypeFile, models.HostRuleTargetTypeDirectory} {
		if _, err := NormalizeConfig(targetType, &models.StaticServeConfig{Path: pathValue}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NormalizeConfig(%q, %q) error = %v, want ErrInvalidConfig", targetType, pathValue, err)
		}
		probe := ProbePath(targetType, pathValue)
		if probe.ErrorCode != ProbeErrorInvalidPath {
			t.Errorf("ProbePath(%q, %q) = %#v, want invalid_path", targetType, pathValue, probe)
		}
	}
}
