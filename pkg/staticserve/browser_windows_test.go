//go:build windows

package staticserve

import (
	"context"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestBrowseWindowsVirtualRootListsOnlyLocalDriveRoots(t *testing.T) {
	result := BrowsePath(context.Background(), models.HostRuleTargetTypeDirectory, "", "")
	if result.ErrorCode != "" {
		t.Fatalf("virtual root error = %q", result.ErrorCode)
	}
	if result.Platform != "windows" || result.CurrentPath != nil || result.ParentPath != nil || result.SelectedPath != nil || result.CurrentSelectable || len(result.Breadcrumbs) != 0 {
		t.Fatalf("virtual root metadata = %#v", result)
	}
	if len(result.Entries) == 0 {
		t.Fatal("Windows virtual root did not expose a local drive")
	}
	for _, entry := range result.Entries {
		if !validWindowsDriveRoot(entry.Path) || entry.EntryType != models.HostRuleTargetTypeDirectory || !entry.Navigable || entry.Selectable {
			t.Errorf("drive entry = %#v", entry)
		}
	}
}

func TestBrowseWindowsBreadcrumbAndDriveParentContract(t *testing.T) {
	breadcrumbs, ok := browseBreadcrumbs(`C:\Users\Public`)
	if !ok {
		t.Fatal("Windows breadcrumbs were rejected")
	}
	want := []BrowseBreadcrumb{
		{Name: "C:", Path: `C:\`},
		{Name: "Users", Path: `C:\Users`},
		{Name: "Public", Path: `C:\Users\Public`},
	}
	if len(breadcrumbs) != len(want) {
		t.Fatalf("breadcrumbs = %#v", breadcrumbs)
	}
	for index := range want {
		if breadcrumbs[index] != want[index] {
			t.Fatalf("breadcrumb %d = %#v, want %#v", index, breadcrumbs[index], want[index])
		}
	}
	parent := browseParentPath(`C:\`)
	if parent == nil || *parent != "" {
		t.Fatalf("drive root parent = %#v, want virtual root", parent)
	}
}

func TestBrowseWindowsRejectsNetworkAndDeviceNamespaces(t *testing.T) {
	for _, pathValue := range []string{`\\server\share`, `\\?\C:\Windows`, `\\.\pipe\name`, `\??\C:\Windows`} {
		if _, code := normalizeBrowsePath(pathValue); code != BrowseErrorInvalidPath {
			t.Errorf("normalizeBrowsePath(%q) code = %q", pathValue, code)
		}
	}
}
