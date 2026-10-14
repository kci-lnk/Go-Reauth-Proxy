package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectPageDefaultsSurviveInitialSaveAndLegacyMigration(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"portal":{"enabled":false}}`, `{"portal":{"select_page_enabled":false}}`} {
		t.Run(raw, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.json")
			if raw != "" {
				if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
					t.Fatal(err)
				}
			}
			manager := NewManager(file)
			want := raw != `{"portal":{"select_page_enabled":false}}`
			for i := 0; i < 2; i++ {
				cfg, err := manager.Load()
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Portal.IsSelectPageEnabled() != want {
					t.Fatalf("load %d: enabled=%v, want %v", i, cfg.Portal.IsSelectPageEnabled(), want)
				}
			}
		})
	}
}
