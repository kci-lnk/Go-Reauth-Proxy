package staticserve

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"go-reauth-proxy/pkg/models"
	"golang.org/x/net/html"
)

func TestListingFeatureFileSizeBoundaries(t *testing.T) {
	testCases := []struct {
		name string
		size int64
		want string
	}{
		{name: "negative", size: -1, want: "—"},
		{name: "zero", size: 0, want: "0 B"},
		{name: "last byte", size: 1023, want: "1023 B"},
		{name: "one kilobyte", size: 1 << 10, want: "1 KB"},
		{name: "fractional kilobyte", size: 1536, want: "1.5 KB"},
		{name: "whole kilobytes omit decimal", size: 2 << 10, want: "2 KB"},
		{name: "last value displayed below one megabyte", size: 1_048_524, want: "1023.9 KB"},
		{name: "first rounded value promoted to one megabyte", size: 1_048_525, want: "1 MB"},
		{name: "byte below exact megabyte", size: (1 << 20) - 1, want: "1 MB"},
		{name: "one megabyte", size: 1 << 20, want: "1 MB"},
		{name: "fractional megabyte", size: (1 << 20) + (1 << 19), want: "1.5 MB"},
		{name: "last value displayed below one gigabyte", size: 1_073_689_395, want: "1023.9 MB"},
		{name: "first rounded value promoted to one gigabyte", size: 1_073_689_396, want: "1 GB"},
		{name: "byte below exact gigabyte", size: (1 << 30) - 1, want: "1 GB"},
		{name: "one gigabyte", size: 1 << 30, want: "1 GB"},
		{name: "last value displayed below one terabyte", size: 1_099_457_940_684, want: "1023.9 GB"},
		{name: "first rounded value promoted to one terabyte", size: 1_099_457_940_685, want: "1 TB"},
		{name: "byte below exact terabyte", size: (1 << 40) - 1, want: "1 TB"},
		{name: "one terabyte", size: 1 << 40, want: "1 TB"},
		{name: "last value displayed below one petabyte", size: 1_125_844_931_261_235, want: "1023.9 TB"},
		{name: "first rounded value promoted to one petabyte", size: 1_125_844_931_261_236, want: "1 PB"},
		{name: "byte below exact petabyte", size: (1 << 50) - 1, want: "1 PB"},
		{name: "one petabyte", size: 1 << 50, want: "1 PB"},
		{name: "last value displayed below one exabyte", size: 1_152_865_209_611_504_844, want: "1023.9 PB"},
		{name: "first rounded value promoted to one exabyte", size: 1_152_865_209_611_504_845, want: "1 EB"},
		{name: "byte below exact exabyte", size: (1 << 60) - 1, want: "1 EB"},
		{name: "one exabyte", size: 1 << 60, want: "1 EB"},
		{name: "largest int64", size: int64(1<<63 - 1), want: "8 EB"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := formatFileSize(testCase.size); got != testCase.want {
				t.Fatalf("formatFileSize(%d) = %q, want %q", testCase.size, got, testCase.want)
			}
		})
	}
}

func TestListingFeatureModifiedTimeUsesBeijing(t *testing.T) {
	input := time.Date(2026, time.August, 30, 5, 48, 7, 987_654_321, time.UTC)
	display, machine := formatModifiedTime(input)
	if display != "2026-08-30 13:48:07" {
		t.Fatalf("display time = %q, want Beijing wall time", display)
	}
	if machine != "2026-08-30T13:48:07+08:00" {
		t.Fatalf("machine time = %q, want RFC3339 with +08:00", machine)
	}

	otherLocation := input.In(time.FixedZone("test-west", -7*60*60))
	otherDisplay, otherMachine := formatModifiedTime(otherLocation)
	if otherDisplay != display || otherMachine != machine {
		t.Fatalf("same instant in another location = (%q, %q), want (%q, %q)", otherDisplay, otherMachine, display, machine)
	}

	if zeroDisplay, zeroMachine := formatModifiedTime(time.Time{}); zeroDisplay != "" || zeroMachine != "" {
		t.Fatalf("zero time = (%q, %q), want empty values", zeroDisplay, zeroMachine)
	}
}

func TestListingFeatureAllSortModesKeepDirectoriesFirstAndBreakTiesByName(t *testing.T) {
	base := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	candidates := []listingCandidate{
		{key: newListingKey(false, "large.txt"), size: 30, modified: base.Add(30 * time.Second)},
		{key: newListingKey(true, "zulu-dir"), modified: base.Add(10 * time.Second)},
		{key: newListingKey(false, "same-b.txt"), size: 10, modified: base.Add(20 * time.Second)},
		{key: newListingKey(false, "small.txt"), size: 5, modified: base.Add(10 * time.Second)},
		{key: newListingKey(true, "alpha-dir"), modified: base.Add(30 * time.Second)},
		{key: newListingKey(false, "same-a.txt"), size: 10, modified: base.Add(20 * time.Second)},
	}

	testCases := []struct {
		name string
		sort listingSort
		want []string
	}{
		{
			name: "name ascending",
			sort: listingSort{field: listingSortByName, order: listingSortAscending},
			want: []string{"alpha-dir", "zulu-dir", "large.txt", "same-a.txt", "same-b.txt", "small.txt"},
		},
		{
			name: "name descending",
			sort: listingSort{field: listingSortByName, order: listingSortDescending},
			want: []string{"zulu-dir", "alpha-dir", "small.txt", "same-b.txt", "same-a.txt", "large.txt"},
		},
		{
			name: "size ascending",
			sort: listingSort{field: listingSortBySize, order: listingSortAscending},
			want: []string{"alpha-dir", "zulu-dir", "small.txt", "same-a.txt", "same-b.txt", "large.txt"},
		},
		{
			name: "size descending",
			sort: listingSort{field: listingSortBySize, order: listingSortDescending},
			want: []string{"alpha-dir", "zulu-dir", "large.txt", "same-a.txt", "same-b.txt", "small.txt"},
		},
		{
			name: "modified ascending",
			sort: listingSort{field: listingSortByModified, order: listingSortAscending},
			want: []string{"zulu-dir", "alpha-dir", "small.txt", "same-a.txt", "same-b.txt", "large.txt"},
		},
		{
			name: "modified descending",
			sort: listingSort{field: listingSortByModified, order: listingSortDescending},
			want: []string{"alpha-dir", "zulu-dir", "large.txt", "same-a.txt", "same-b.txt", "small.txt"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotCandidates := append([]listingCandidate(nil), candidates...)
			sort.Slice(gotCandidates, func(i, j int) bool {
				return compareListingCandidates(gotCandidates[i], gotCandidates[j], testCase.sort) < 0
			})
			got := make([]string, 0, len(gotCandidates))
			for _, candidate := range gotCandidates {
				got = append(got, candidate.key.name)
			}
			if !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("sorted names = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestListingFeatureSortDefaultsAndToggleLinks(t *testing.T) {
	parseCases := []struct {
		raw  string
		want listingSort
	}{
		{raw: "", want: listingSort{field: listingSortByName, order: listingSortAscending}},
		{raw: "order=desc", want: listingSort{field: listingSortByName, order: listingSortDescending}},
		{raw: "sort=size", want: listingSort{field: listingSortBySize, order: listingSortDescending}},
		{raw: "sort=modified", want: listingSort{field: listingSortByModified, order: listingSortDescending}},
		{raw: "sort=size&order=asc", want: listingSort{field: listingSortBySize, order: listingSortAscending}},
	}
	for _, testCase := range parseCases {
		query, err := url.ParseQuery(testCase.raw)
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseListingSort(query)
		if err != nil {
			t.Fatalf("parseListingSort(%q): %v", testCase.raw, err)
		}
		if got != testCase.want {
			t.Fatalf("parseListingSort(%q) = %#v, want %#v", testCase.raw, got, testCase.want)
		}
	}

	linkCases := []struct {
		name       string
		active     listingSort
		wantOrders []string
		wantAria   string
	}{
		{
			name:       "default name ascending",
			active:     listingSort{field: listingSortByName, order: listingSortAscending},
			wantOrders: []string{"desc", "desc", "desc"},
			wantAria:   "ascending",
		},
		{
			name:       "size descending toggles ascending",
			active:     listingSort{field: listingSortBySize, order: listingSortDescending},
			wantOrders: []string{"asc", "asc", "desc"},
			wantAria:   "descending",
		},
		{
			name:       "modified ascending toggles descending",
			active:     listingSort{field: listingSortByModified, order: listingSortAscending},
			wantOrders: []string{"asc", "desc", "desc"},
			wantAria:   "ascending",
		},
	}
	fields := []string{"name", "size", "modified"}
	for _, testCase := range linkCases {
		t.Run(testCase.name, func(t *testing.T) {
			links := listingSortLinks(testCase.active)
			if len(links) != len(fields) {
				t.Fatalf("sort link count = %d, want %d", len(links), len(fields))
			}
			for index, link := range links {
				parsed, err := url.Parse(link.Href)
				if err != nil {
					t.Fatal(err)
				}
				query := parsed.Query()
				if query.Get("sort") != fields[index] || query.Get("order") != testCase.wantOrders[index] {
					t.Errorf("link %s target = %q, want sort=%s order=%s", link.Label, link.Href, fields[index], testCase.wantOrders[index])
				}
				if query.Has("cursor") {
					t.Errorf("sort link %q retained a cursor", link.Href)
				}
				wantActive := listingSortField(index) == testCase.active.field
				if link.Active != wantActive {
					t.Errorf("link %s Active = %t, want %t", link.Label, link.Active, wantActive)
				}
				if wantActive && link.AriaSort != testCase.wantAria {
					t.Errorf("active link %s aria-sort = %q, want %q", link.Label, link.AriaSort, testCase.wantAria)
				}
				if !wantActive && link.AriaSort != "" {
					t.Errorf("inactive link %s aria-sort = %q, want empty", link.Label, link.AriaSort)
				}
				wantIndicator := "unsorted"
				if wantActive {
					wantIndicator = testCase.wantAria
				}
				if link.Indicator != wantIndicator {
					t.Errorf("link %s indicator = %q, want %q", link.Label, link.Indicator, wantIndicator)
				}
			}
		})
	}
}

func TestListingFeatureRejectsInvalidSortQuery(t *testing.T) {
	root := t.TempDir()
	cfg := listingConfig(root, false)
	testCases := []string{
		"sort=",
		"sort=unknown",
		"sort=name&sort=size",
		"sort=name&sort=name",
		"order=",
		"order=sideways",
		"order=asc&order=desc",
		"order=asc&order=asc",
		"sort=%zz",
	}

	for _, rawQuery := range testCases {
		t.Run(rawQuery, func(t *testing.T) {
			response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/?"+rawQuery, nil, Options{})
			if response.Code != http.StatusBadRequest {
				t.Fatalf("query %q = %d %q, want 400", rawQuery, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), root) {
				t.Fatalf("query %q leaked filesystem root in %q", rawQuery, response.Body.String())
			}
		})
	}
}

func TestListingFeatureLegacyCursorCompatibilityAndNewCursorSortBinding(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"file-a.txt", "file-b.txt", "file-c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := listingConfig(root, false)

	legacyPayload := append([]byte{byte(cursorAfter), 1}, []byte("file-a.txt")...)
	legacyCursor := base64.RawURLEncoding.EncodeToString(legacyPayload)
	for _, requestPath := range []string{
		"/?cursor=" + url.QueryEscape(legacyCursor),
		"/?sort=name&order=asc&cursor=" + url.QueryEscape(legacyCursor),
	} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusOK {
			t.Fatalf("legacy cursor request %q = %d %q", requestPath, response.Code, response.Body.String())
		}
		if got, want := listingFeatureEntryNames(t, response.Body.String()), []string{"file-b.txt", "file-c.txt"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("legacy cursor entries = %v, want %v", got, want)
		}
	}

	for _, requestPath := range []string{
		"/?sort=name&order=desc&cursor=" + url.QueryEscape(legacyCursor),
		"/?sort=size&order=desc&cursor=" + url.QueryEscape(legacyCursor),
		"/?sort=modified&order=desc&cursor=" + url.QueryEscape(legacyCursor),
	} {
		legacyMismatch := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if legacyMismatch.Code != http.StatusBadRequest {
			t.Fatalf("legacy cursor with non-default sort %q = %d %q, want 400", requestPath, legacyMismatch.Code, legacyMismatch.Body.String())
		}
	}

	sortSpec := listingSort{field: listingSortBySize, order: listingSortDescending}
	newCursor := encodeListingCursor(cursorAfter, sortSpec, listingCandidate{
		key:      newListingKey(false, "file-b.txt"),
		size:     int64(len("file-b.txt")),
		modified: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
	})
	correct := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/?sort=size&order=desc&cursor="+url.QueryEscape(newCursor), nil, Options{})
	if correct.Code != http.StatusOK {
		t.Fatalf("new cursor with matching sort = %d %q", correct.Code, correct.Body.String())
	}
	for _, requestPath := range []string{
		"/?sort=size&order=asc&cursor=" + url.QueryEscape(newCursor),
		"/?sort=modified&order=desc&cursor=" + url.QueryEscape(newCursor),
		"/?cursor=" + url.QueryEscape(newCursor),
	} {
		response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("new cursor sort mismatch %q = %d %q, want 400", requestPath, response.Code, response.Body.String())
		}
	}
}

func TestListingFeatureVersionedCursorRoundTripsRawComparisonKeys(t *testing.T) {
	sortSpec := listingSort{field: listingSortByModified, order: listingSortDescending}
	candidate := listingCandidate{
		key:      newListingKey(true, "archive?#%.data"),
		size:     (1 << 40) + 37,
		modified: time.Date(2026, time.August, 30, 5, 48, 7, 987_654_321, time.UTC),
	}
	encoded := encodeListingCursor(cursorBefore, sortSpec, candidate)
	decoded, err := decodeListingCursor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.direction != cursorBefore || decoded.sort != sortSpec {
		t.Fatalf("decoded cursor metadata = direction %d sort %#v", decoded.direction, decoded.sort)
	}
	if decoded.candidate.key.directory != candidate.key.directory ||
		decoded.candidate.key.name != candidate.key.name ||
		decoded.candidate.size != candidate.size ||
		!decoded.candidate.modified.Equal(candidate.modified) ||
		decoded.candidate.modified.Nanosecond() != candidate.modified.Nanosecond() {
		t.Fatalf("decoded cursor candidate = %#v, want %#v", decoded.candidate, candidate)
	}
}

func TestListingFeatureRejectsMalformedVersionedCursorFields(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	validCursor := encodeListingCursor(cursorAfter, defaultListingSort, listingCandidate{
		key:      newListingKey(false, "visible.txt"),
		size:     4,
		modified: time.Date(2026, time.August, 30, 5, 48, 7, 123, time.UTC),
	})
	validPayload, err := base64.RawURLEncoding.DecodeString(validCursor)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown version", mutate: func(payload []byte) []byte { payload[0] = listingCursorVersion + 1; return payload }},
		{name: "invalid direction", mutate: func(payload []byte) []byte { payload[1] = byte(cursorBefore) + 1; return payload }},
		{name: "invalid field", mutate: func(payload []byte) []byte { payload[2] = byte(listingSortByModified) + 1; return payload }},
		{name: "invalid order", mutate: func(payload []byte) []byte { payload[3] = byte(listingSortDescending) + 1; return payload }},
		{name: "invalid type", mutate: func(payload []byte) []byte { payload[4] = 2; return payload }},
		{name: "negative size", mutate: func(payload []byte) []byte { payload[5] |= 0x80; return payload }},
		{name: "invalid nanoseconds", mutate: func(payload []byte) []byte {
			binary.BigEndian.PutUint32(payload[21:25], 1_000_000_000)
			return payload
		}},
		{name: "empty name", mutate: func(payload []byte) []byte { return payload[:listingCursorHeaderSize] }},
		{name: "unsafe name", mutate: func(payload []byte) []byte {
			return append(append([]byte(nil), payload[:listingCursorHeaderSize]...), []byte("bad/name")...)
		}},
	}
	cfg := listingConfig(root, false)
	for _, testCase := range mutations {
		t.Run(testCase.name, func(t *testing.T) {
			payload := testCase.mutate(append([]byte(nil), validPayload...))
			cursor := base64.RawURLEncoding.EncodeToString(payload)
			response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/?cursor="+url.QueryEscape(cursor), nil, Options{})
			if response.Code != http.StatusBadRequest || response.Body.String() != "Invalid directory cursor\n" {
				t.Fatalf("malformed v2 cursor = %d %q, want 400", response.Code, response.Body.String())
			}
		})
	}
}

func TestListingFeatureParentHrefEscapesSpecialPathSegmentsAndPreservesSort(t *testing.T) {
	root := t.TempDir()
	parentName := "parent?#%"
	childName := "child?#%"
	if err := os.MkdirAll(filepath.Join(root, parentName, childName), 0o755); err != nil {
		t.Fatal(err)
	}
	requestPath := "/" + url.PathEscape(parentName) + "/" + url.PathEscape(childName) + "/?sort=size&order=desc"
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(root, false), http.MethodGet, requestPath, nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("special-character child listing = %d %q", response.Code, response.Body.String())
	}

	parentHref := listingFeatureAnchorHrefByAttribute(t, response.Body.String(), "aria-label", "Parent directory")
	parsed, err := url.Parse(parentHref)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := "/" + url.PathEscape(parentName) + "/"
	if got := parsed.EscapedPath(); got != wantPath {
		t.Fatalf("parent href %q escaped path = %q, want %q", parentHref, got, wantPath)
	}
	query := parsed.Query()
	if got := query["sort"]; len(got) != 1 || got[0] != "size" {
		t.Fatalf("parent href %q sort values = %v, want [size]", parentHref, got)
	}
	if got := query["order"]; len(got) != 1 || got[0] != "desc" {
		t.Fatalf("parent href %q order values = %v, want [desc]", parentHref, got)
	}
}

func TestListingFeatureNavigationLinksPreserveSortOnlyForDirectories(t *testing.T) {
	root := t.TempDir()
	parentName := "parent?#%"
	currentName := "current"
	currentPath := filepath.Join(root, parentName, currentName)
	if err := os.MkdirAll(filepath.Join(currentPath, "nested?#%"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(currentPath, "file?#%.txt"), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	requestPath := "/" + url.PathEscape(parentName) + "/" + url.PathEscape(currentName) + "/?sort=modified&order=asc"
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, listingConfig(root, false), http.MethodGet, requestPath, nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("nested listing = %d %q", response.Code, response.Body.String())
	}

	document, err := html.Parse(strings.NewReader(response.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	breadcrumbs := listingFeatureElementByClass(document, "nav", "breadcrumbs")
	if breadcrumbs == nil {
		t.Fatal("breadcrumbs missing")
	}
	breadcrumbCount := 0
	currentCount := 0
	listingFeatureWalk(breadcrumbs, func(node *html.Node) {
		if node.Type != html.ElementNode || node.Data != "a" {
			return
		}
		breadcrumbCount++
		listingFeatureAssertDirectorySortState(t, listingFeatureAttribute(node, "href"), "modified", "asc")
		if listingFeatureAttribute(node, "aria-current") == "page" {
			currentCount++
		}
	})
	if breadcrumbCount != 3 || currentCount != 1 {
		t.Fatalf("breadcrumbs = %d links and %d current links, want 3 and 1", breadcrumbCount, currentCount)
	}

	table := listingFeatureElementByClass(document, "table", "listing-table")
	if table == nil {
		t.Fatal("listing table missing")
	}
	var directoryHref, fileHref string
	listingFeatureWalk(table, func(node *html.Node) {
		if node.Type != html.ElementNode || node.Data != "a" {
			return
		}
		text := strings.TrimSpace(listingFeatureNodeText(node))
		switch text {
		case "nested?#%/":
			directoryHref = listingFeatureAttribute(node, "href")
		case "file?#%.txt":
			fileHref = listingFeatureAttribute(node, "href")
		}
	})
	if directoryHref == "" || fileHref == "" {
		t.Fatalf("directory href %q or file href %q missing", directoryHref, fileHref)
	}
	listingFeatureAssertDirectorySortState(t, directoryHref, "modified", "asc")
	parsedFile, err := url.Parse(fileHref)
	if err != nil {
		t.Fatal(err)
	}
	if parsedFile.RawQuery != "" {
		t.Fatalf("file href %q unexpectedly retained sort state", fileHref)
	}
	if parsedFile.EscapedPath() != "./"+url.PathEscape("file?#%.txt") {
		t.Fatalf("file href escaped path = %q, want %q", parsedFile.EscapedPath(), "./"+url.PathEscape("file?#%.txt"))
	}
}

func TestListingFeatureColonNamesRemainRelativeSameOriginLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("colon is not a portable Windows filename character")
	}

	root := t.TempDir()
	fileName := "report:2026.txt"
	directoryName := "archive:2026"
	if err := os.WriteFile(filepath.Join(root, fileName), []byte("body"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, directoryName), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := listingConfig(root, false)
	response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/?sort=size&order=desc", nil, Options{})
	if response.Code != http.StatusOK {
		t.Fatalf("listing = %d %q", response.Code, response.Body.String())
	}

	document, err := html.Parse(strings.NewReader(response.Body.String()))
	if err != nil {
		t.Fatal(err)
	}
	links := make(map[string]string)
	listingFeatureWalk(listingFeatureElementByClass(document, "table", "listing-table"), func(node *html.Node) {
		if node.Type != html.ElementNode || node.Data != "a" {
			return
		}
		links[strings.TrimSuffix(strings.TrimSpace(listingFeatureNodeText(node)), "/")] = listingFeatureAttribute(node, "href")
	})

	for _, name := range []string{fileName, directoryName} {
		href := links[name]
		if !strings.HasPrefix(href, "./") || strings.Contains(href, "#ZgotmplZ") {
			t.Fatalf("href for %q = %q, want explicit safe relative reference", name, href)
		}
		parsed, parseErr := url.Parse(href)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		if parsed.Scheme != "" || parsed.Host != "" {
			t.Fatalf("href for %q escaped the current origin: %q", name, href)
		}
	}

	fileHref := links[fileName]
	if parsed, parseErr := url.Parse(fileHref); parseErr != nil || parsed.RawQuery != "" {
		t.Fatalf("file href = %q, parse error %v; want no sort query", fileHref, parseErr)
	}
	fileResponse := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/"+url.PathEscape(fileName), nil, Options{})
	if fileResponse.Code != http.StatusOK || fileResponse.Body.String() != "body" {
		t.Fatalf("colon file request = %d %q", fileResponse.Code, fileResponse.Body.String())
	}

	directoryHref := links[directoryName]
	listingFeatureAssertDirectorySortState(t, directoryHref, "size", "desc")
	directoryResponse := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, "/"+url.PathEscape(directoryName)+"/?sort=size&order=desc", nil, Options{})
	if directoryResponse.Code != http.StatusOK {
		t.Fatalf("colon directory request = %d %q", directoryResponse.Code, directoryResponse.Body.String())
	}
}

func TestListingFeaturePaginationIsGlobalForAllSortModesAndPreservesSort(t *testing.T) {
	root := t.TempDir()
	base := time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	fixtures := make([]listingFeatureFixture, 0, 205)
	for index := 0; index < 205; index++ {
		fixture := listingFeatureFixture{
			name:     fmt.Sprintf("item-%03d.dat", index),
			size:     int64(index%7 + 1),
			modified: base.Add(time.Duration(index%5) * time.Second),
		}
		listingFeatureWriteFile(t, root, fixture)
		fixtures = append(fixtures, fixture)
	}
	cfg := listingConfig(root, false)

	testCases := []struct {
		field string
		order string
	}{
		{field: "name", order: "asc"},
		{field: "name", order: "desc"},
		{field: "size", order: "asc"},
		{field: "size", order: "desc"},
		{field: "modified", order: "asc"},
		{field: "modified", order: "desc"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.field+" "+testCase.order, func(t *testing.T) {
			want := listingFeatureExpectedOrder(fixtures, testCase.field, testCase.order)
			requestPath := "/?sort=" + testCase.field + "&order=" + testCase.order
			var got []string
			pages := 0
			for {
				response := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, requestPath, nil, Options{})
				if response.Code != http.StatusOK {
					t.Fatalf("page %d = %d %q", pages+1, response.Code, response.Body.String())
				}
				pageNames := listingFeatureEntryNames(t, response.Body.String())
				got = append(got, pageNames...)
				pages++

				if pages == 2 {
					previousHref, ok := listingFeatureRelationHref(t, response.Body.String(), "prev")
					if !ok {
						t.Fatal("second page omitted previous link")
					}
					listingFeatureAssertSortQuery(t, previousHref, testCase.field, testCase.order)
					back := serveRequest(t, models.HostRuleTargetTypeDirectory, cfg, http.MethodGet, listingFeatureRequestPath(t, previousHref), nil, Options{})
					if back.Code != http.StatusOK {
						t.Fatalf("previous page = %d %q", back.Code, back.Body.String())
					}
					if backNames := listingFeatureEntryNames(t, back.Body.String()); !reflect.DeepEqual(backNames, want[:DefaultPageSize]) {
						t.Fatalf("previous link returned first page %v, want %v", backNames, want[:DefaultPageSize])
					}
				}

				nextHref, ok := listingFeatureRelationHref(t, response.Body.String(), "next")
				if !ok {
					break
				}
				listingFeatureAssertSortQuery(t, nextHref, testCase.field, testCase.order)
				requestPath = listingFeatureRequestPath(t, nextHref)
				if pages > 10 {
					t.Fatal("pagination did not terminate")
				}
			}

			if pages != 3 {
				t.Fatalf("page count = %d, want 3", pages)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("combined pagination order differs\ngot:  %v\nwant: %v", got, want)
			}
		})
	}
}

type listingFeatureFixture struct {
	name     string
	size     int64
	modified time.Time
}

func listingFeatureWriteFile(t *testing.T, root string, fixture listingFeatureFixture) {
	t.Helper()
	content := bytes.Repeat([]byte{'x'}, int(fixture.size))
	path := filepath.Join(root, fixture.name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fixture.modified, fixture.modified); err != nil {
		t.Fatal(err)
	}
}

func listingFeatureExpectedOrder(fixtures []listingFeatureFixture, field, order string) []string {
	ordered := append([]listingFeatureFixture(nil), fixtures...)
	sort.Slice(ordered, func(i, j int) bool {
		comparison := 0
		switch field {
		case "name":
			comparison = strings.Compare(ordered[i].name, ordered[j].name)
		case "size":
			switch {
			case ordered[i].size < ordered[j].size:
				comparison = -1
			case ordered[i].size > ordered[j].size:
				comparison = 1
			}
		case "modified":
			comparison = ordered[i].modified.Compare(ordered[j].modified)
		}
		if comparison != 0 {
			if order == "desc" {
				return comparison > 0
			}
			return comparison < 0
		}
		return ordered[i].name < ordered[j].name
	})
	result := make([]string, 0, len(ordered))
	for _, fixture := range ordered {
		result = append(result, fixture.name)
	}
	return result
}

func listingFeatureEntryNames(t *testing.T, body string) []string {
	t.Helper()
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	table := listingFeatureElementByClass(document, "table", "listing-table")
	if table == nil {
		t.Fatal("listing table missing")
	}
	var result []string
	listingFeatureWalk(table, func(node *html.Node) {
		if node.Type != html.ElementNode || node.Data != "tr" || listingFeatureHasClass(node, "parent-entry") {
			return
		}
		nameCell := listingFeatureElementByClass(node, "td", "name")
		if nameCell == nil {
			return
		}
		anchor := listingFeatureFirstElement(nameCell, "a")
		if anchor == nil {
			return
		}
		name := strings.TrimSpace(listingFeatureNodeText(anchor))
		name = strings.TrimSuffix(name, "/")
		if name != "" && name != ".." {
			result = append(result, name)
		}
	})
	return result
}

func listingFeatureRelationHref(t *testing.T, body, relation string) (string, bool) {
	t.Helper()
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var href string
	listingFeatureWalk(document, func(node *html.Node) {
		if href != "" || node.Type != html.ElementNode || node.Data != "a" {
			return
		}
		if !listingFeatureAttributeContainsWord(node, "rel", relation) {
			return
		}
		href = listingFeatureAttribute(node, "href")
	})
	return href, href != ""
}

func listingFeatureAnchorHrefByAttribute(t *testing.T, body, attributeName, attributeValue string) string {
	t.Helper()
	document, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var href string
	listingFeatureWalk(document, func(node *html.Node) {
		if href == "" && node.Type == html.ElementNode && node.Data == "a" && listingFeatureAttribute(node, attributeName) == attributeValue {
			href = listingFeatureAttribute(node, "href")
		}
	})
	if href == "" {
		t.Fatalf("anchor with %s=%q missing", attributeName, attributeValue)
	}
	return href
}

func listingFeatureAssertSortQuery(t *testing.T, href, field, order string) {
	t.Helper()
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if got := query["sort"]; len(got) != 1 || got[0] != field {
		t.Fatalf("href %q sort values = %v, want [%s]", href, got, field)
	}
	if got := query["order"]; len(got) != 1 || got[0] != order {
		t.Fatalf("href %q order values = %v, want [%s]", href, got, order)
	}
	if got := query["cursor"]; len(got) != 1 || got[0] == "" {
		t.Fatalf("href %q cursor values = %v, want one opaque cursor", href, got)
	}
}

func listingFeatureAssertDirectorySortState(t *testing.T, href, field, order string) {
	t.Helper()
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if got := query["sort"]; len(got) != 1 || got[0] != field {
		t.Fatalf("href %q sort values = %v, want [%s]", href, got, field)
	}
	if got := query["order"]; len(got) != 1 || got[0] != order {
		t.Fatalf("href %q order values = %v, want [%s]", href, got, order)
	}
	if query.Has("cursor") {
		t.Fatalf("directory navigation href %q unexpectedly retained cursor", href)
	}
}

func listingFeatureRequestPath(t *testing.T, href string) string {
	t.Helper()
	parsed, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func listingFeatureElementByClass(root *html.Node, element, class string) *html.Node {
	var result *html.Node
	listingFeatureWalk(root, func(node *html.Node) {
		if result == nil && node.Type == html.ElementNode && node.Data == element && listingFeatureHasClass(node, class) {
			result = node
		}
	})
	return result
}

func listingFeatureFirstElement(root *html.Node, element string) *html.Node {
	var result *html.Node
	listingFeatureWalk(root, func(node *html.Node) {
		if result == nil && node.Type == html.ElementNode && node.Data == element {
			result = node
		}
	})
	return result
}

func listingFeatureHasClass(node *html.Node, class string) bool {
	return listingFeatureAttributeContainsWord(node, "class", class)
}

func listingFeatureAttributeContainsWord(node *html.Node, name, word string) bool {
	for _, value := range strings.Fields(listingFeatureAttribute(node, name)) {
		if value == word {
			return true
		}
	}
	return false
}

func listingFeatureAttribute(node *html.Node, name string) string {
	for _, attribute := range node.Attr {
		if attribute.Key == name {
			return attribute.Val
		}
	}
	return ""
}

func listingFeatureNodeText(root *html.Node) string {
	var result strings.Builder
	listingFeatureWalk(root, func(node *html.Node) {
		if node.Type == html.TextNode {
			result.WriteString(node.Data)
		}
	})
	return result.String()
}

func listingFeatureWalk(root *html.Node, visit func(*html.Node)) {
	visit(root)
	for child := root.FirstChild; child != nil; child = child.NextSibling {
		listingFeatureWalk(child, visit)
	}
}
