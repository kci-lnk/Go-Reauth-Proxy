package staticserve

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"go-reauth-proxy/pkg/models"
)

const (
	BrowsePageSize       = 100
	MaxBrowsePathBytes   = 4096
	MaxBrowseBreadcrumbs = 256
	MaxBrowseCursorBytes = 512

	BrowseErrorInvalidPath       = "invalid_path"
	BrowseErrorInvalidCursor     = "invalid_cursor"
	BrowseErrorProtectedPath     = "protected_path"
	BrowseErrorNotFound          = "not_found"
	BrowseErrorPermissionDenied  = "permission_denied"
	BrowseErrorNotDirectory      = "not_directory"
	BrowseErrorDirectoryTooLarge = "directory_too_large"
	BrowseErrorUnsupportedType   = "unsupported_type"
	BrowseErrorUnavailable       = "unavailable"
)

const (
	browseCursorVersion    = byte(1)
	browseCursorHeaderSize = 19
	browseVirtualRootKey   = "\x00windows-local-drives"
)

type BrowseBreadcrumb struct {
	Name string
	Path string
}

type BrowseEntry struct {
	Name       string
	Path       string
	EntryType  string
	Navigable  bool
	Selectable bool
	SizeBytes  *uint64
	ModifiedAt *string
}

type BrowseResult struct {
	TargetType        string
	Platform          string
	CurrentPath       *string
	ParentPath        *string
	CurrentSelectable bool
	SelectedPath      *string
	Breadcrumbs       []BrowseBreadcrumb
	Entries           []BrowseEntry
	PreviousCursor    string
	NextCursor        string
	ErrorCode         string
}

type browseProtectionState byte

const (
	browseProtectionNormal browseProtectionState = iota
	browseProtectionAncestor
	browseProtectionHidden
)

type browsePathPolicy struct {
	protected []string
}

func newBrowsePathPolicy(protectedPaths ...string) *browsePathPolicy {
	policy := &browsePathPolicy{}
	seen := make(map[string]struct{}, len(protectedPaths)*2)
	for _, protected := range protectedPaths {
		protected = strings.TrimSpace(protected)
		if protected == "" {
			continue
		}
		for _, protectedPath := range comparablePaths(protected) {
			protectedPath = filepath.Clean(protectedPath)
			if _, ok := seen[protectedPath]; ok {
				continue
			}
			seen[protectedPath] = struct{}{}
			policy.protected = append(policy.protected, protectedPath)
		}
	}
	return policy
}

func (policy *browsePathPolicy) protection(candidate string) browseProtectionState {
	state := browseProtectionNormal
	for _, candidatePath := range comparablePaths(candidate) {
		for _, protectedPath := range policy.protected {
			if pathContains(protectedPath, candidatePath) {
				return browseProtectionHidden
			}
			if pathContains(candidatePath, protectedPath) {
				state = browseProtectionAncestor
			}
		}
	}
	return state
}

type browseCursor struct {
	direction cursorDirection
	key       listingKey
}

type browseCandidate struct {
	key   listingKey
	entry BrowseEntry
}

type browseCandidateHeap struct {
	values  []browseCandidate
	minimum bool
}

func (h browseCandidateHeap) Len() int { return len(h.values) }
func (h browseCandidateHeap) Less(i, j int) bool {
	comparison := compareListingKeys(h.values[i].key, h.values[j].key)
	if h.minimum {
		return comparison < 0
	}
	return comparison > 0
}
func (h browseCandidateHeap) Swap(i, j int) { h.values[i], h.values[j] = h.values[j], h.values[i] }
func (h *browseCandidateHeap) Push(value any) {
	h.values = append(h.values, value.(browseCandidate))
}
func (h *browseCandidateHeap) Pop() any {
	old := h.values
	last := old[len(old)-1]
	h.values = old[:len(old)-1]
	return last
}

type browsePageCollector struct {
	cursor         *browseCursor
	forward        bool
	forwardValues  *browseCandidateHeap
	backwardValues *browseCandidateHeap
}

func newBrowsePageCollector(cursor *browseCursor) *browsePageCollector {
	forward := cursor == nil || cursor.direction == cursorAfter
	collector := &browsePageCollector{
		cursor:         cursor,
		forward:        forward,
		forwardValues:  &browseCandidateHeap{},
		backwardValues: &browseCandidateHeap{minimum: true},
	}
	heap.Init(collector.forwardValues)
	heap.Init(collector.backwardValues)
	return collector
}

func (collector *browsePageCollector) add(candidate browseCandidate) {
	if collector.cursor != nil {
		comparison := compareListingKeys(candidate.key, collector.cursor.key)
		if (collector.forward && comparison <= 0) || (!collector.forward && comparison >= 0) {
			return
		}
	}
	if collector.forward {
		if collector.forwardValues.Len() < BrowsePageSize+1 {
			heap.Push(collector.forwardValues, candidate)
		} else if compareListingKeys(candidate.key, collector.forwardValues.values[0].key) < 0 {
			heap.Pop(collector.forwardValues)
			heap.Push(collector.forwardValues, candidate)
		}
		return
	}
	if collector.backwardValues.Len() < BrowsePageSize+1 {
		heap.Push(collector.backwardValues, candidate)
	} else if compareListingKeys(candidate.key, collector.backwardValues.values[0].key) > 0 {
		heap.Pop(collector.backwardValues)
		heap.Push(collector.backwardValues, candidate)
	}
}

func (collector *browsePageCollector) finish(bindingPath, targetType string) ([]BrowseEntry, string, string) {
	values := collector.forwardValues.values
	if !collector.forward {
		values = collector.backwardValues.values
	}
	sort.Slice(values, func(i, j int) bool {
		return compareListingKeys(values[i].key, values[j].key) < 0
	})
	hasPrevious := collector.forward && collector.cursor != nil
	hasNext := false
	if collector.forward && len(values) > BrowsePageSize {
		values = values[:BrowsePageSize]
		hasNext = true
	} else if !collector.forward && len(values) > BrowsePageSize {
		values = values[len(values)-BrowsePageSize:]
		hasPrevious = true
	}
	if !collector.forward {
		hasNext = true
	}
	if len(values) == 0 {
		hasPrevious, hasNext = false, false
	}

	entries := make([]BrowseEntry, 0, len(values))
	for _, value := range values {
		entries = append(entries, value.entry)
	}
	previousCursor, nextCursor := "", ""
	if hasPrevious {
		previousCursor = encodeBrowseCursor(cursorBefore, bindingPath, targetType, values[0].key)
	}
	if hasNext {
		nextCursor = encodeBrowseCursor(cursorAfter, bindingPath, targetType, values[len(values)-1].key)
	}
	return entries, previousCursor, nextCursor
}

// BrowsePath returns one bounded page from the gateway process's visible
// filesystem. It is an administrative convenience only: ProbePath and each
// static data-plane open remain authoritative after a user makes a selection.
func BrowsePath(ctx context.Context, targetType, pathValue, cursorValue string, protectedPaths ...string) BrowseResult {
	targetType = models.NormalizeHostRuleTargetType(targetType)
	result := BrowseResult{TargetType: targetType, Platform: browsePlatform()}
	if targetType != models.HostRuleTargetTypeFile && targetType != models.HostRuleTargetTypeDirectory {
		result.ErrorCode = BrowseErrorUnsupportedType
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pathPolicy := newBrowsePathPolicy(protectedPaths...)

	if pathValue == "" && runtime.GOOS == "windows" {
		return browseWindowsVirtualRoot(ctx, result, cursorValue, pathPolicy)
	}
	if pathValue == "" {
		pathValue = string(filepath.Separator)
	}
	normalizedPath, errorCode := normalizeBrowsePathWithPolicy(pathValue, pathPolicy)
	if errorCode != "" {
		result.ErrorCode = errorCode
		return result
	}

	resolvedTarget, targetInfo, errorCode := inspectBrowseRequestTarget(normalizedPath, pathPolicy)
	if errorCode != "" {
		result.ErrorCode = errorCode
		return result
	}
	if !targetInfo.IsDir() && !targetInfo.Mode().IsRegular() {
		result.ErrorCode = BrowseErrorUnsupportedType
		return result
	}

	currentPath := normalizedPath
	resolvedCurrent := resolvedTarget
	expectedCurrentInfo := targetInfo
	var selectedPath *string
	if targetInfo.Mode().IsRegular() {
		if targetType == models.HostRuleTargetTypeDirectory {
			result.ErrorCode = BrowseErrorNotDirectory
			return result
		}
		selected := normalizedPath
		selectedPath = &selected
		currentPath = filepath.Dir(normalizedPath)
		resolvedCurrent, errorCode = resolveBrowseDirectory(currentPath, pathPolicy)
		if errorCode != "" {
			result.ErrorCode = errorCode
			return result
		}
		currentInfo, statErr := os.Stat(resolvedCurrent)
		if statErr != nil {
			result.ErrorCode = classifyBrowseError(statErr)
			return result
		}
		expectedCurrentInfo = currentInfo
	}

	breadcrumbs, ok := browseBreadcrumbs(currentPath)
	if !ok {
		result.ErrorCode = BrowseErrorInvalidPath
		return result
	}
	cursor, err := decodeBrowseCursor(cursorValue, currentPath, targetType, false)
	if err != nil {
		result.ErrorCode = BrowseErrorInvalidCursor
		return result
	}

	root, err := openBrowseDirectoryRootWithPolicy(resolvedCurrent, pathPolicy)
	if err != nil {
		result.ErrorCode = classifyBrowseError(err)
		return result
	}
	defer root.Close()
	openedInfo, err := root.pinned.Stat()
	if err != nil || expectedCurrentInfo == nil || !os.SameFile(expectedCurrentInfo, openedInfo) {
		result.ErrorCode = BrowseErrorUnavailable
		return result
	}
	directory, err := openRootFileForRead(root, ".")
	if err != nil {
		result.ErrorCode = classifyBrowseError(err)
		return result
	}
	defer directory.Close()

	entries, previousCursor, nextCursor, err := scanBrowseDirectoryPage(ctx, root, directory, currentPath, targetType, cursor, pathPolicy)
	if err != nil {
		result.ErrorCode = classifyBrowseError(err)
		return result
	}
	current := currentPath
	result.CurrentPath = &current
	result.ParentPath = browseParentPath(currentPath)
	result.CurrentSelectable = targetType == models.HostRuleTargetTypeDirectory && browseDirectorySelectable(currentPath, pathPolicy)
	result.SelectedPath = selectedPath
	result.Breadcrumbs = breadcrumbs
	result.Entries = entries
	result.PreviousCursor = previousCursor
	result.NextCursor = nextCursor
	return result
}

func normalizeBrowsePath(pathValue string, protectedPaths ...string) (string, string) {
	return normalizeBrowsePathWithPolicy(pathValue, newBrowsePathPolicy(protectedPaths...))
}

func normalizeBrowsePathWithPolicy(pathValue string, pathPolicy *browsePathPolicy) (string, string) {
	if len(pathValue) > MaxBrowsePathBytes || !utf8.ValidString(pathValue) || strings.IndexByte(pathValue, 0) >= 0 {
		return "", BrowseErrorInvalidPath
	}
	if windowsUNCPath(pathValue) || (runtime.GOOS == "windows" && unsafeWindowsStaticPath(pathValue)) {
		return "", BrowseErrorInvalidPath
	}
	if runtime.GOOS != "windows" && strings.Contains(pathValue, "\\") {
		return "", BrowseErrorInvalidPath
	}
	if !filepath.IsAbs(pathValue) {
		return "", BrowseErrorInvalidPath
	}
	normalized := filepath.Clean(pathValue)
	if len(normalized) > MaxBrowsePathBytes {
		return "", BrowseErrorInvalidPath
	}
	if pathPolicy.protection(normalized) == browseProtectionHidden {
		return "", BrowseErrorProtectedPath
	}
	components := splitPathComponents(strings.TrimPrefix(normalized, filepath.VolumeName(normalized)))
	if len(components) > MaxBrowseBreadcrumbs-1 {
		return "", BrowseErrorInvalidPath
	}
	for _, component := range components {
		if !safeBrowseName(component) {
			return "", BrowseErrorInvalidPath
		}
	}
	return normalized, ""
}

func safeBrowseName(name string) bool {
	return len(name) <= 255 && utf8.RuneCountInString(name) <= 255 && safeVisibleName(name) && !strings.HasPrefix(name, "__")
}

func inspectBrowseRequestTarget(pathValue string, pathPolicy *browsePathPolicy) (string, os.FileInfo, string) {
	if pathPolicy.protection(pathValue) == browseProtectionHidden {
		return "", nil, BrowseErrorProtectedPath
	}
	if filepath.Dir(pathValue) == pathValue {
		resolved, err := filepath.EvalSymlinks(pathValue)
		if err != nil {
			return "", nil, classifyBrowseError(err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return "", nil, classifyBrowseError(err)
		}
		if !info.IsDir() {
			return "", nil, BrowseErrorNotDirectory
		}
		if pathPolicy.protection(resolved) == browseProtectionHidden {
			return "", nil, BrowseErrorProtectedPath
		}
		return filepath.Clean(resolved), info, ""
	}

	parentPath := filepath.Dir(pathValue)
	resolvedParent, errorCode := resolveBrowseDirectory(parentPath, pathPolicy)
	if errorCode != "" {
		return "", nil, errorCode
	}
	root, err := openBrowseDirectoryRootWithPolicy(resolvedParent, pathPolicy)
	if err != nil {
		return "", nil, classifyBrowseError(err)
	}
	defer root.Close()
	name := filepath.Base(pathValue)
	entryInfo, err := root.Lstat(name)
	if err != nil {
		return "", nil, classifyBrowseError(err)
	}
	if !entryInfo.IsDir() && !entryInfo.Mode().IsRegular() && entryInfo.Mode()&os.ModeSymlink == 0 {
		return "", nil, BrowseErrorUnsupportedType
	}
	if entryInfo.Mode()&os.ModeSymlink != 0 {
		if _, ok := resolveVisibleBrowseTarget(root.Name(), name); !ok {
			return "", nil, BrowseErrorInvalidPath
		}
	}
	opened, err := openRootFileForRead(root, name)
	if err != nil {
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return "", nil, BrowseErrorInvalidPath
		}
		return "", nil, classifyBrowseError(err)
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil {
		return "", nil, classifyBrowseError(err)
	}
	resolvedTarget, ok := resolveVisibleBrowseTarget(root.Name(), name)
	if !ok {
		return "", nil, BrowseErrorInvalidPath
	}
	resolvedInfo, err := os.Stat(resolvedTarget)
	if err != nil || !os.SameFile(info, resolvedInfo) {
		return "", nil, BrowseErrorUnavailable
	}
	if pathPolicy.protection(resolvedTarget) == browseProtectionHidden {
		return "", nil, BrowseErrorProtectedPath
	}
	return resolvedTarget, info, ""
}

func resolveBrowseDirectory(pathValue string, pathPolicy *browsePathPolicy) (string, string) {
	resolved, info, errorCode := inspectBrowseRequestTarget(pathValue, pathPolicy)
	if errorCode != "" {
		return "", errorCode
	}
	if !info.IsDir() {
		return "", BrowseErrorNotDirectory
	}
	return resolved, ""
}

func openBrowseDirectoryRoot(pathValue string, protectedPaths ...string) (*staticDirectoryRoot, error) {
	return openBrowseDirectoryRootWithPolicy(pathValue, newBrowsePathPolicy(protectedPaths...))
}

func openBrowseDirectoryRootWithPolicy(pathValue string, pathPolicy *browsePathPolicy) (*staticDirectoryRoot, error) {
	return openBrowseDirectoryRootAfterPreopen(pathValue, nil, pathPolicy)
}

func openBrowseDirectoryRootAfterPreopen(pathValue string, afterPreopen func(), pathPolicy *browsePathPolicy) (*staticDirectoryRoot, error) {
	return openStaticDirectoryRootWithValidator(pathValue, afterPreopen, func(resolvedPath string) error {
		if pathPolicy.protection(resolvedPath) == browseProtectionHidden {
			return ErrProtectedPath
		}
		return nil
	})
}

func scanBrowseDirectoryPage(ctx context.Context, root rootedFileOpener, directory *os.File, currentPath, targetType string, cursor *browseCursor, pathPolicy *browsePathPolicy) ([]BrowseEntry, string, string, error) {
	return scanBrowseDirectoryPageWithPolicyAndLimits(ctx, root, directory, currentPath, targetType, cursor, MaxDirectoryScannedEntries, MaxDirectoryVisibleEntries, pathPolicy)
}

func scanBrowseDirectoryPageWithLimits(ctx context.Context, root rootedFileOpener, directory *os.File, currentPath, targetType string, cursor *browseCursor, maxScannedEntries, maxVisibleEntries int, protectedPaths ...string) ([]BrowseEntry, string, string, error) {
	return scanBrowseDirectoryPageWithPolicyAndLimits(ctx, root, directory, currentPath, targetType, cursor, maxScannedEntries, maxVisibleEntries, newBrowsePathPolicy(protectedPaths...))
}

func scanBrowseDirectoryPageWithPolicyAndLimits(ctx context.Context, root rootedFileOpener, directory *os.File, currentPath, targetType string, cursor *browseCursor, maxScannedEntries, maxVisibleEntries int, pathPolicy *browsePathPolicy) ([]BrowseEntry, string, string, error) {
	const batchSize = 1024
	collector := newBrowsePageCollector(cursor)
	scanned, visible := 0, 0
	for {
		select {
		case <-ctx.Done():
			return nil, "", "", ctx.Err()
		default:
		}
		batch, err := directory.ReadDir(batchSize)
		for _, directoryEntry := range batch {
			select {
			case <-ctx.Done():
				return nil, "", "", ctx.Err()
			default:
			}
			scanned++
			if scanned > maxScannedEntries {
				return nil, "", "", errDirectoryTooLarge
			}
			candidate, ok := inspectBrowseCandidate(root, currentPath, targetType, directoryEntry, pathPolicy)
			if !ok {
				continue
			}
			visible++
			if visible > maxVisibleEntries {
				return nil, "", "", errDirectoryTooLarge
			}
			collector.add(candidate)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", "", err
		}
	}
	entries, previousCursor, nextCursor := collector.finish(currentPath, targetType)
	return entries, previousCursor, nextCursor, nil
}

func inspectBrowseCandidate(root rootedFileOpener, currentPath, targetType string, directoryEntry os.DirEntry, pathPolicy *browsePathPolicy) (browseCandidate, bool) {
	name := directoryEntry.Name()
	if !safeBrowseName(name) {
		return browseCandidate{}, false
	}
	visiblePath := filepath.Join(currentPath, name)
	if len(visiblePath) > MaxBrowsePathBytes {
		return browseCandidate{}, false
	}
	protection := pathPolicy.protection(visiblePath)
	if protection == browseProtectionHidden {
		return browseCandidate{}, false
	}
	if directoryEntry.Type()&os.ModeSymlink != 0 {
		if _, ok := resolveVisibleBrowseTarget(root.Name(), name); !ok {
			return browseCandidate{}, false
		}
	}
	opened, err := openRootFileForRead(root, name)
	if err != nil {
		return browseCandidate{}, false
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		return browseCandidate{}, false
	}
	resolvedTarget, ok := resolveVisibleBrowseTarget(root.Name(), name)
	if !ok {
		return browseCandidate{}, false
	}
	resolvedInfo, err := os.Stat(resolvedTarget)
	if err != nil || !os.SameFile(info, resolvedInfo) {
		return browseCandidate{}, false
	}
	resolvedProtection := pathPolicy.protection(resolvedTarget)
	if resolvedProtection == browseProtectionHidden {
		return browseCandidate{}, false
	}
	if resolvedProtection == browseProtectionAncestor {
		protection = browseProtectionAncestor
	}

	entryType := models.HostRuleTargetTypeFile
	navigable := false
	if info.IsDir() {
		entryType = models.HostRuleTargetTypeDirectory
		navigable = true
	}
	selectable := protection == browseProtectionNormal && ((targetType == models.HostRuleTargetTypeDirectory && info.IsDir()) || (targetType == models.HostRuleTargetTypeFile && info.Mode().IsRegular()))
	entry := BrowseEntry{
		Name:       name,
		Path:       visiblePath,
		EntryType:  entryType,
		Navigable:  navigable,
		Selectable: selectable,
	}
	if info.Mode().IsRegular() {
		size := uint64(info.Size())
		entry.SizeBytes = &size
	}
	if !info.ModTime().IsZero() {
		modifiedAt := info.ModTime().UTC().Format(time.RFC3339Nano)
		entry.ModifiedAt = &modifiedAt
	}
	return browseCandidate{key: newListingKey(info.IsDir(), name), entry: entry}, true
}

// resolveVisibleBrowseTarget applies the browser's stricter visible-name
// policy to the fully resolved target. openRootFileForRead intentionally uses
// the serving policy, which permits internal __* names; browsing must also
// hide visible aliases that resolve through such an internal component.
// Symlinks receive an advisory check before opening, every target is checked
// after opening, and the descriptor SameFile check closes a symlink exchange.
func resolveVisibleBrowseTarget(rootPath, name string) (string, bool) {
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Clean(rootPath))
	if err != nil {
		return "", false
	}
	resolvedTarget, err := filepath.EvalSymlinks(filepath.Join(rootPath, filepath.FromSlash(name)))
	if err != nil {
		return "", false
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	resolvedTarget = filepath.Clean(resolvedTarget)
	relative, err := filepath.Rel(resolvedRoot, resolvedTarget)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", false
	}
	if relative != "." {
		for _, component := range splitPathComponents(relative) {
			if !safeBrowseName(component) {
				return "", false
			}
		}
	}
	return resolvedTarget, true
}

func browseProtection(candidate string, protectedPaths ...string) browseProtectionState {
	return newBrowsePathPolicy(protectedPaths...).protection(candidate)
}

func browseDirectorySelectable(pathValue string, pathPolicy *browsePathPolicy) bool {
	return filepath.Dir(pathValue) != pathValue && pathPolicy.protection(pathValue) == browseProtectionNormal
}

func browseBreadcrumbs(pathValue string) ([]BrowseBreadcrumb, bool) {
	pathValue = filepath.Clean(pathValue)
	volume := filepath.VolumeName(pathValue)
	components := splitPathComponents(strings.TrimPrefix(pathValue, volume))
	if len(components) > MaxBrowseBreadcrumbs-1 {
		return nil, false
	}
	if runtime.GOOS == "windows" {
		if volume == "" {
			return nil, false
		}
		rootPath := volume + string(filepath.Separator)
		result := []BrowseBreadcrumb{{Name: volume, Path: rootPath}}
		current := rootPath
		for _, component := range components {
			current = filepath.Join(current, component)
			result = append(result, BrowseBreadcrumb{Name: component, Path: current})
		}
		return result, true
	}
	result := []BrowseBreadcrumb{{Name: string(filepath.Separator), Path: string(filepath.Separator)}}
	current := string(filepath.Separator)
	for _, component := range components {
		current = filepath.Join(current, component)
		result = append(result, BrowseBreadcrumb{Name: component, Path: current})
	}
	return result, true
}

func browseParentPath(pathValue string) *string {
	parent := filepath.Dir(pathValue)
	if parent != pathValue {
		return &parent
	}
	if runtime.GOOS == "windows" {
		virtualRoot := ""
		return &virtualRoot
	}
	return nil
}

func browsePlatform() string {
	if runtime.GOOS == "windows" {
		return "windows"
	}
	return "posix"
}

func encodeBrowseCursor(direction cursorDirection, bindingPath, targetType string, key listingKey) string {
	binding := browseCursorBinding(bindingPath, targetType)
	payload := make([]byte, browseCursorHeaderSize, browseCursorHeaderSize+len(key.name))
	payload[0] = browseCursorVersion
	payload[1] = byte(direction)
	if key.directory {
		payload[2] = 1
	}
	copy(payload[3:19], binding[:])
	payload = append(payload, key.name...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeBrowseCursor(value, bindingPath, targetType string, virtualRoot bool) (*browseCursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > MaxBrowseCursorBytes {
		return nil, errors.New("browse cursor is too long")
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return nil, errors.New("browse cursor is not base64url")
		}
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) <= browseCursorHeaderSize || payload[0] != browseCursorVersion || payload[1] > byte(cursorBefore) || payload[2] > 1 {
		return nil, errors.New("browse cursor is malformed")
	}
	binding := browseCursorBinding(bindingPath, targetType)
	if !equalFixedBytes(payload[3:19], binding[:]) {
		return nil, errors.New("browse cursor binding does not match")
	}
	name := string(payload[browseCursorHeaderSize:])
	if (!virtualRoot && !safeBrowseName(name)) || (virtualRoot && !validWindowsDriveRoot(name)) {
		return nil, errors.New("browse cursor name is invalid")
	}
	return &browseCursor{direction: cursorDirection(payload[1]), key: newListingKey(payload[2] == 1, name)}, nil
}

func browseCursorBinding(pathValue, targetType string) [16]byte {
	hash := sha256.Sum256([]byte(browsePlatform() + "\x00" + targetType + "\x00" + pathValue))
	var binding [16]byte
	copy(binding[:], hash[:16])
	return binding
}

func equalFixedBytes(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	difference := byte(0)
	for index := range first {
		difference |= first[index] ^ second[index]
	}
	return difference == 0
}

func browseWindowsVirtualRoot(ctx context.Context, result BrowseResult, cursorValue string, pathPolicy *browsePathPolicy) BrowseResult {
	drives, err := browseDriveRoots()
	if err != nil {
		result.ErrorCode = BrowseErrorUnavailable
		return result
	}
	cursor, err := decodeBrowseCursor(cursorValue, browseVirtualRootKey, result.TargetType, true)
	if err != nil {
		result.ErrorCode = BrowseErrorInvalidCursor
		return result
	}
	collector := newBrowsePageCollector(cursor)
	for _, drive := range drives {
		select {
		case <-ctx.Done():
			result.ErrorCode = BrowseErrorUnavailable
			return result
		default:
		}
		if pathPolicy.protection(drive) == browseProtectionHidden {
			continue
		}
		collector.add(browseCandidate{
			key: newListingKey(true, drive),
			entry: BrowseEntry{
				Name:       strings.TrimSuffix(drive, string(filepath.Separator)),
				Path:       drive,
				EntryType:  models.HostRuleTargetTypeDirectory,
				Navigable:  true,
				Selectable: false,
			},
		})
	}
	result.Entries, result.PreviousCursor, result.NextCursor = collector.finish(browseVirtualRootKey, result.TargetType)
	return result
}

func classifyBrowseError(err error) string {
	switch {
	case errors.Is(err, ErrProtectedPath):
		return BrowseErrorProtectedPath
	case errors.Is(err, os.ErrNotExist):
		return BrowseErrorNotFound
	case errors.Is(err, os.ErrPermission):
		return BrowseErrorPermissionDenied
	case errors.Is(err, errDirectoryTooLarge):
		return BrowseErrorDirectoryTooLarge
	case errors.Is(err, errUnsafeRootTarget), errors.Is(err, ErrInvalidConfig):
		return BrowseErrorInvalidPath
	default:
		return BrowseErrorUnavailable
	}
}
