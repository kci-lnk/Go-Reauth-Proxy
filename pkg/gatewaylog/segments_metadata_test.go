package gatewaylog

import (
	"fmt"
	"testing"

	"go-reauth-proxy/pkg/models"
)

func TestLogSegmentsExposeFlushedRecordsWhileWriterRemainsOpen(t *testing.T) {
	m := NewManager(t.TempDir(), models.LoggingConfig{Enabled: true})
	defer m.Close()

	// Query and analyze between appends, keeping the same writer handle open.
	// This also exercises cache refresh when an active segment grows on NTFS.
	for count := 1; count <= 3; count++ {
		m.Log(Entry{TraceID: fmt.Sprint(count), Status: 200, Path: "/active"})
		m.Flush()
		m.writer.mu.Lock()
		info, err := m.writer.currentFile.Stat()
		m.writer.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		segments, err := listLogSegments(m.LogsDir())
		if err != nil || len(segments) != 1 {
			t.Fatalf("segments: %+v, err=%v", segments, err)
		}
		if segments[0].size != info.Size() || segments[0].size == 0 {
			t.Fatalf("active segment size = %d, handle size = %d", segments[0].size, info.Size())
		}

		page, err := m.Query("", 1, 20, "", "", "", "", "", "page")
		if err != nil || page.Total != count || len(page.Items) != count {
			t.Fatalf("page after %d appends: %+v, err=%v", count, page, err)
		}
		cursor := ""
		for want := count; want >= 1; want-- {
			page, err := m.Query("", 1, 1, "", "", "", "", cursor, "cursor")
			if err != nil || len(page.Items) != 1 || page.Items[0].TraceID != fmt.Sprint(want) {
				t.Fatalf("cursor entry %d: %+v, err=%v", want, page, err)
			}
			if page.HasMore != (want > 1) || (want > 1 && page.NextCursor == "") {
				t.Fatalf("cursor continuation for entry %d: %+v", want, page)
			}
			cursor = page.NextCursor
		}
		analysis, err := m.Analyze("", "")
		if err != nil || analysis.Summary.Requests != int64(count) {
			t.Fatalf("analysis after %d appends: %+v, err=%v", count, analysis.Summary, err)
		}
	}
}
