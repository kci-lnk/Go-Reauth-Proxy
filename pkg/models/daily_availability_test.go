package models

import (
	"testing"
	"time"
)

func TestDailyAvailabilityOpenAt(t *testing.T) {
	daytime := &DailyAvailability{Enabled: true, StartTime: "09:00", EndTime: "18:00"}
	if !DailyAvailabilityOpenAt(daytime, time.Date(2026, 1, 1, 9, 0, 0, 0, time.Local)) {
		t.Fatal("daytime window should include its start")
	}
	if DailyAvailabilityOpenAt(daytime, time.Date(2026, 1, 1, 18, 0, 0, 0, time.Local)) {
		t.Fatal("daytime window should exclude its end")
	}

	overnight := &DailyAvailability{Enabled: true, StartTime: "22:00", EndTime: "06:00"}
	if !DailyAvailabilityOpenAt(overnight, time.Date(2026, 1, 1, 2, 0, 0, 0, time.Local)) {
		t.Fatal("overnight window should include the next-day portion")
	}
	if DailyAvailabilityOpenAt(overnight, time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)) {
		t.Fatal("overnight window should be closed at noon")
	}
}

func TestNormalizeDailyAvailability(t *testing.T) {
	normalized, err := NormalizeDailyAvailability(&DailyAvailability{
		Enabled: true, StartTime: " 22:00 ", EndTime: "06:00",
	})
	if err != nil || normalized.StartTime != "22:00" || normalized.EndTime != "06:00" {
		t.Fatalf("normalized = %#v, err = %v", normalized, err)
	}
	if _, err := NormalizeDailyAvailability(&DailyAvailability{
		Enabled: true, StartTime: "09:00", EndTime: "09:00",
	}); err == nil {
		t.Fatal("equal start and end should be rejected")
	}
}
