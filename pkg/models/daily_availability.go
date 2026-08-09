package models

import (
	"fmt"
	"strings"
	"time"
)

func NormalizeDailyAvailability(value *DailyAvailability) (*DailyAvailability, error) {
	if value == nil || !value.Enabled {
		return nil, nil
	}

	startTime := strings.TrimSpace(value.StartTime)
	endTime := strings.TrimSpace(value.EndTime)
	startMinute, ok := parseDailyAvailabilityMinute(startTime)
	if !ok {
		return nil, fmt.Errorf("availability start_time must use HH:mm")
	}
	endMinute, ok := parseDailyAvailabilityMinute(endTime)
	if !ok {
		return nil, fmt.Errorf("availability end_time must use HH:mm")
	}
	if startMinute == endMinute {
		return nil, fmt.Errorf("availability start_time and end_time must be different")
	}

	return &DailyAvailability{
		Enabled:   true,
		StartTime: startTime,
		EndTime:   endTime,
	}, nil
}

func DailyAvailabilityOpenAt(value *DailyAvailability, now time.Time) bool {
	if value == nil || !value.Enabled {
		return true
	}

	startMinute, startOK := parseDailyAvailabilityMinute(strings.TrimSpace(value.StartTime))
	endMinute, endOK := parseDailyAvailabilityMinute(strings.TrimSpace(value.EndTime))
	if !startOK || !endOK || startMinute == endMinute {
		return true
	}
	currentMinute := now.Local().Hour()*60 + now.Local().Minute()
	if startMinute < endMinute {
		return currentMinute >= startMinute && currentMinute < endMinute
	}
	return currentMinute >= startMinute || currentMinute < endMinute
}

func FormatDailyAvailabilityWindow(value *DailyAvailability) string {
	if value == nil {
		return ""
	}
	startTime := strings.TrimSpace(value.StartTime)
	endTime := strings.TrimSpace(value.EndTime)
	if startTime == "" || endTime == "" {
		return ""
	}
	return startTime + "-" + endTime
}

func CopyDailyAvailability(value *DailyAvailability) *DailyAvailability {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func parseDailyAvailabilityMinute(value string) (int, bool) {
	if len(value) != 5 || value[2] != ':' {
		return 0, false
	}
	hour, ok := parseTwoDigitDailyAvailabilityPart(value[0], value[1])
	if !ok || hour > 23 {
		return 0, false
	}
	minute, ok := parseTwoDigitDailyAvailabilityPart(value[3], value[4])
	if !ok || minute > 59 {
		return 0, false
	}
	return hour*60 + minute, true
}

func parseTwoDigitDailyAvailabilityPart(a byte, b byte) (int, bool) {
	if a < '0' || a > '9' || b < '0' || b > '9' {
		return 0, false
	}
	return int(a-'0')*10 + int(b-'0'), true
}
