package staticserve

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/base64"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go-reauth-proxy/pkg/models"
)

var errDirectoryTooLarge = errors.New("directory exceeds scan limit")

type listingKey struct {
	directory bool
	name      string
	folded    string
}

type cursorDirection byte

const (
	cursorAfter cursorDirection = iota
	cursorBefore
)

type listingCursor struct {
	direction cursorDirection
	key       listingKey
}

type listingCandidate struct {
	key      listingKey
	size     int64
	modified time.Time
}

type listingCandidateHeap []listingCandidate

func (h listingCandidateHeap) Len() int { return len(h) }
func (h listingCandidateHeap) Less(i, j int) bool {
	return compareListingKeys(h[i].key, h[j].key) > 0
}
func (h listingCandidateHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *listingCandidateHeap) Push(value any) {
	*h = append(*h, value.(listingCandidate))
}
func (h *listingCandidateHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

type listingCandidateMinHeap []listingCandidate

func (h listingCandidateMinHeap) Len() int { return len(h) }
func (h listingCandidateMinHeap) Less(i, j int) bool {
	return compareListingKeys(h[i].key, h[j].key) < 0
}
func (h listingCandidateMinHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *listingCandidateMinHeap) Push(value any) {
	*h = append(*h, value.(listingCandidate))
}
func (h *listingCandidateMinHeap) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

type listingEntryView struct {
	Name         string
	Href         string
	Directory    bool
	Size         string
	Modified     string
	ModifiedTime string
}

type breadcrumbView struct {
	Name string
	Href string
}

type listingPageView struct {
	Title        string
	Breadcrumbs  []breadcrumbView
	Entries      []listingEntryView
	ParentHref   string
	PreviousHref string
	NextHref     string
	README       template.HTML
}

const listingPageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var listingPageTemplate = template.Must(template.New("directory-listing").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}}</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { box-sizing: border-box; max-width: 72rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; line-height: 1.5; }
    a { color: #2563eb; text-decoration: none; } a:hover { text-decoration: underline; }
    nav { overflow-wrap: anywhere; margin-bottom: 1rem; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid color-mix(in srgb, currentColor 18%, transparent); padding: .65rem .5rem; text-align: left; }
    th:nth-child(2), td:nth-child(2) { text-align: right; white-space: nowrap; }
    th:nth-child(3), td:nth-child(3) { white-space: nowrap; }
    .name { overflow-wrap: anywhere; }
    .pager { display: flex; justify-content: space-between; gap: 1rem; margin-top: 1rem; }
    .readme { margin-top: 2.5rem; padding-top: 1.5rem; border-top: 1px solid color-mix(in srgb, currentColor 22%, transparent); overflow-wrap: anywhere; }
    .readme pre { overflow: auto; padding: 1rem; border-radius: .4rem; background: color-mix(in srgb, currentColor 8%, transparent); }
    .readme img { max-width: 100%; height: auto; }
    .readme table { display: block; overflow-x: auto; }
    @media (max-width: 42rem) { th:nth-child(2), td:nth-child(2), th:nth-child(3), td:nth-child(3) { display: none; } }
  </style>
</head>
<body>
  <nav aria-label="Breadcrumb">{{range $index, $part := .Breadcrumbs}}{{if $index}} / {{end}}<a href="{{$part.Href}}">{{$part.Name}}</a>{{end}}</nav>
  <h1>{{.Title}}</h1>
  <table>
    <thead><tr><th>Name</th><th>Size</th><th>Modified</th></tr></thead>
    <tbody>
      {{if .ParentHref}}<tr><td class="name"><a href="{{.ParentHref}}">../</a></td><td>—</td><td></td></tr>{{end}}
      {{range .Entries}}<tr><td class="name"><a href="{{.Href}}">{{.Name}}{{if .Directory}}/{{end}}</a></td><td>{{.Size}}</td><td><time datetime="{{.ModifiedTime}}">{{.Modified}}</time></td></tr>{{end}}
    </tbody>
  </table>
  {{if or .PreviousHref .NextHref}}<div class="pager"><span>{{if .PreviousHref}}<a rel="prev" href="{{.PreviousHref}}">← Previous page</a>{{end}}</span><span>{{if .NextHref}}<a rel="next" href="{{.NextHref}}">Next page →</a>{{end}}</span></div>{{end}}
  {{if .README}}<article class="readme">{{.README}}</article>{{end}}
</body>
</html>`))

func (s *Server) serveDirectoryListing(w http.ResponseWriter, r *http.Request, root rootedFileOpener, directory *os.File, rootName string, cfg *models.StaticServeConfig) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	cursorValues, cursorPresent := query["cursor"]
	invalidCursorValues := len(cursorValues) > 1 ||
		(cursorPresent && (len(cursorValues) != 1 || cursorValues[0] == ""))
	if err != nil || invalidCursorValues {
		writeError(w, r, http.StatusBadRequest, "Invalid directory cursor")
		return
	}
	cursorValue := ""
	if cursorPresent {
		cursorValue = cursorValues[0]
	}
	cursor, err := decodeListingCursor(cursorValue)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "Invalid directory cursor")
		return
	}
	candidates, previousCursor, nextCursor, err := scanDirectoryPage(r.Context(), root, directory, rootName, cursor)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if errors.Is(err, errDirectoryTooLarge) || rootName == "." {
			writeRootUnavailable(w, r)
		} else {
			writeError(w, r, http.StatusNotFound, "Not found")
		}
		return
	}

	entries := make([]listingEntryView, 0, len(candidates))
	for _, candidate := range candidates {
		href := url.PathEscape(candidate.key.name)
		size := formatFileSize(candidate.size)
		if candidate.key.directory {
			href += "/"
			size = "—"
		}
		modified, machineTime := formatModifiedTime(candidate.modified)
		entries = append(entries, listingEntryView{
			Name:         candidate.key.name,
			Href:         href,
			Directory:    candidate.key.directory,
			Size:         size,
			Modified:     modified,
			ModifiedTime: machineTime,
		})
	}

	readme := template.HTML("")
	if cfg.DirectoryListing.RenderReadme {
		readme = s.readme.render(root, joinRootName(rootName, "README.md"))
	}
	view := listingPageView{
		Title:       "Index of " + r.URL.Path,
		Breadcrumbs: listingBreadcrumbs(r.URL.Path),
		Entries:     entries,
		ParentHref:  listingParentHref(r.URL.Path),
		README:      readme,
	}
	if nextCursor != "" {
		view.NextHref = "?cursor=" + url.QueryEscape(nextCursor)
	}
	if previousCursor != "" {
		view.PreviousHref = "?cursor=" + url.QueryEscape(previousCursor)
	}

	var body bytes.Buffer
	if err := listingPageTemplate.Execute(&body, view); err != nil {
		writeRootUnavailable(w, r)
		return
	}
	w.Header().Set("Cache-Control", generatedCacheControl)
	w.Header().Set("Content-Security-Policy", listingPageCSP)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body.Bytes())
	}
}

func scanDirectoryPage(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, cursor *listingCursor) ([]listingCandidate, string, string, error) {
	return scanDirectoryPageWithLimits(ctx, root, directory, rootName, cursor, MaxDirectoryScannedEntries, MaxDirectoryVisibleEntries)
}

func scanDirectoryPageWithLimit(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, cursor *listingCursor, maxEntries int) ([]listingCandidate, string, string, error) {
	return scanDirectoryPageWithLimits(ctx, root, directory, rootName, cursor, maxEntries, maxEntries)
}

func scanDirectoryPageWithLimits(ctx context.Context, root rootedFileOpener, directory *os.File, rootName string, cursor *listingCursor, maxScannedEntries, maxVisibleEntries int) ([]listingCandidate, string, string, error) {
	const batchSize = 1024
	forward := cursor == nil || cursor.direction == cursorAfter
	forwardValues := &listingCandidateHeap{}
	backwardValues := &listingCandidateMinHeap{}
	heap.Init(forwardValues)
	heap.Init(backwardValues)
	scanned := 0
	visible := 0
	for {
		select {
		case <-ctx.Done():
			return nil, "", "", ctx.Err()
		default:
		}
		batch, err := directory.ReadDir(batchSize)
		for _, entry := range batch {
			select {
			case <-ctx.Done():
				return nil, "", "", ctx.Err()
			default:
			}
			scanned++
			if scanned > maxScannedEntries {
				return nil, "", "", errDirectoryTooLarge
			}
			candidate, ok := inspectListingCandidate(root, rootName, entry)
			if !ok {
				continue
			}
			visible++
			if visible > maxVisibleEntries {
				return nil, "", "", errDirectoryTooLarge
			}
			if cursor != nil {
				comparison := compareListingKeys(candidate.key, cursor.key)
				if (forward && comparison <= 0) || (!forward && comparison >= 0) {
					continue
				}
			}
			if forward {
				if forwardValues.Len() < DefaultPageSize+1 {
					heap.Push(forwardValues, candidate)
				} else if compareListingKeys(candidate.key, (*forwardValues)[0].key) < 0 {
					heap.Pop(forwardValues)
					heap.Push(forwardValues, candidate)
				}
			} else {
				if backwardValues.Len() < DefaultPageSize+1 {
					heap.Push(backwardValues, candidate)
				} else if compareListingKeys(candidate.key, (*backwardValues)[0].key) > 0 {
					heap.Pop(backwardValues)
					heap.Push(backwardValues, candidate)
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, "", "", err
		}
	}

	var result []listingCandidate
	if forward {
		result = append(result, (*forwardValues)...)
	} else {
		result = append(result, (*backwardValues)...)
	}
	sort.Slice(result, func(i, j int) bool {
		return compareListingKeys(result[i].key, result[j].key) < 0
	})
	hasPrevious := forward && cursor != nil
	hasNext := false
	if forward && len(result) > DefaultPageSize {
		result = result[:DefaultPageSize]
		hasNext = true
	} else if !forward && len(result) > DefaultPageSize {
		result = result[len(result)-DefaultPageSize:]
		hasPrevious = true
	}
	if !forward {
		hasNext = true
	}
	if len(result) == 0 {
		hasPrevious, hasNext = false, false
	}
	previousCursor := ""
	nextCursor := ""
	if hasPrevious {
		previousCursor = encodeListingCursor(cursorBefore, result[0].key)
	}
	if hasNext {
		nextCursor = encodeListingCursor(cursorAfter, result[len(result)-1].key)
	}
	return result, previousCursor, nextCursor, nil
}

func inspectListingCandidate(root rootedFileOpener, rootName string, entry os.DirEntry) (listingCandidate, bool) {
	name := entry.Name()
	if !safeVisibleName(name) || (rootName == "." && strings.HasPrefix(name, "__")) {
		return listingCandidate{}, false
	}
	info, err := entry.Info()
	if err != nil {
		return listingCandidate{}, false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		file, openErr := openRootFileForRead(root, joinRootName(rootName, name))
		if openErr != nil {
			return listingCandidate{}, false
		}
		info, err = file.Stat()
		file.Close()
		if err != nil {
			return listingCandidate{}, false
		}
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return listingCandidate{}, false
	}
	return listingCandidate{
		key:      newListingKey(info.IsDir(), name),
		size:     info.Size(),
		modified: info.ModTime(),
	}, true
}

func compareListingKeys(first, second listingKey) int {
	if first.directory != second.directory {
		if first.directory {
			return -1
		}
		return 1
	}
	if comparison := strings.Compare(first.folded, second.folded); comparison != 0 {
		return comparison
	}
	return strings.Compare(first.name, second.name)
}

func newListingKey(directory bool, name string) listingKey {
	return listingKey{directory: directory, name: name, folded: strings.ToLower(name)}
}

func encodeListingCursor(direction cursorDirection, key listingKey) string {
	typeByte := byte(1)
	if key.directory {
		typeByte = 0
	}
	payload := append([]byte{byte(direction), typeByte}, []byte(key.name)...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeListingCursor(value string) (*listingCursor, error) {
	if value == "" {
		return nil, nil
	}
	if len(value) > 512 {
		return nil, errors.New("cursor is too long")
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) < 3 || payload[0] > byte(cursorBefore) || payload[1] > 1 {
		return nil, errors.New("cursor is malformed")
	}
	name := string(payload[2:])
	if !safeVisibleName(name) || len(name) > 255 {
		return nil, errors.New("cursor name is invalid")
	}
	return &listingCursor{
		direction: cursorDirection(payload[0]),
		key:       newListingKey(payload[1] == 0, name),
	}, nil
}

func listingBreadcrumbs(requestPath string) []breadcrumbView {
	result := []breadcrumbView{{Name: "root", Href: "/"}}
	trimmed := strings.Trim(requestPath, "/")
	if trimmed == "" {
		return result
	}
	components := strings.Split(trimmed, "/")
	var href strings.Builder
	href.WriteByte('/')
	for _, component := range components {
		href.WriteString(url.PathEscape(component))
		href.WriteByte('/')
		result = append(result, breadcrumbView{Name: component, Href: href.String()})
	}
	return result
}

func listingParentHref(requestPath string) string {
	if requestPath == "/" {
		return ""
	}
	trimmed := strings.TrimSuffix(requestPath, "/")
	index := strings.LastIndexByte(trimmed, '/')
	if index <= 0 {
		return "/"
	}
	return trimmed[:index+1]
}

func formatFileSize(size int64) string {
	if size < 0 {
		return "—"
	}
	return strconv.FormatInt(size, 10) + " B"
}

func formatModifiedTime(value time.Time) (string, string) {
	if value.IsZero() {
		return "", ""
	}
	value = value.UTC()
	return value.Format("2006-01-02 15:04 UTC"), value.Format(time.RFC3339)
}
