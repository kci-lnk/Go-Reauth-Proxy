package proxy

import (
	"fmt"
	"go-reauth-proxy/pkg/models"
	"strings"
	"time"
)

const (
	hostUnavailableReasonDisabled      = "disabled"
	hostUnavailableReasonOutsideWindow = "outside_window"
)

type hostAvailabilityDecision struct {
	Available bool
	Reason    string
	Window    string
}

func normalizeHostRuleAvailability(value *models.HostRuleAvailability) (*models.HostRuleAvailability, error) {
	if value == nil || !value.Enabled {
		return nil, nil
	}

	startTime := strings.TrimSpace(value.StartTime)
	endTime := strings.TrimSpace(value.EndTime)
	startMinute, ok := parseHostAvailabilityMinute(startTime)
	if !ok {
		return nil, fmt.Errorf("availability start_time must use HH:mm")
	}
	endMinute, ok := parseHostAvailabilityMinute(endTime)
	if !ok {
		return nil, fmt.Errorf("availability end_time must use HH:mm")
	}
	if startMinute == endMinute {
		return nil, fmt.Errorf("availability start_time and end_time must be different")
	}

	return &models.HostRuleAvailability{
		Enabled:   true,
		StartTime: startTime,
		EndTime:   endTime,
	}, nil
}

func evaluateHostRuleAvailability(rule *models.HostRule, now time.Time) hostAvailabilityDecision {
	if rule == nil {
		return hostAvailabilityDecision{Available: true}
	}
	if rule.Disabled {
		return hostAvailabilityDecision{
			Available: false,
			Reason:    hostUnavailableReasonDisabled,
		}
	}
	availability := rule.Availability
	if availability == nil || !availability.Enabled {
		return hostAvailabilityDecision{Available: true}
	}

	startMinute, startOK := parseHostAvailabilityMinute(strings.TrimSpace(availability.StartTime))
	endMinute, endOK := parseHostAvailabilityMinute(strings.TrimSpace(availability.EndTime))
	if !startOK || !endOK || startMinute == endMinute {
		return hostAvailabilityDecision{Available: true}
	}

	currentMinute := now.Local().Hour()*60 + now.Local().Minute()
	insideWindow := false
	if startMinute < endMinute {
		insideWindow = currentMinute >= startMinute && currentMinute < endMinute
	} else {
		insideWindow = currentMinute >= startMinute || currentMinute < endMinute
	}
	if insideWindow {
		return hostAvailabilityDecision{
			Available: true,
			Window:    formatHostAvailabilityWindow(availability),
		}
	}
	return hostAvailabilityDecision{
		Available: false,
		Reason:    hostUnavailableReasonOutsideWindow,
		Window:    formatHostAvailabilityWindow(availability),
	}
}

func hostRuleAvailableNow(rule *models.HostRule, now time.Time) bool {
	return evaluateHostRuleAvailability(rule, now).Available
}

func filterAvailableHostRules(hostRules []models.HostRule, now time.Time) []models.HostRule {
	if len(hostRules) == 0 {
		return hostRules
	}
	filtered := make([]models.HostRule, 0, len(hostRules))
	for _, rule := range hostRules {
		if hostRuleAvailableNow(&rule, now) {
			filtered = append(filtered, rule)
		}
	}
	if len(filtered) == len(hostRules) {
		return hostRules
	}
	return filtered
}

func formatHostAvailabilityWindow(value *models.HostRuleAvailability) string {
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

func parseHostAvailabilityMinute(value string) (int, bool) {
	if len(value) != 5 || value[2] != ':' {
		return 0, false
	}
	hour, ok := parseTwoDigitHostAvailabilityPart(value[0], value[1])
	if !ok || hour > 23 {
		return 0, false
	}
	minute, ok := parseTwoDigitHostAvailabilityPart(value[3], value[4])
	if !ok || minute > 59 {
		return 0, false
	}
	return hour*60 + minute, true
}

func parseTwoDigitHostAvailabilityPart(a byte, b byte) (int, bool) {
	if a < '0' || a > '9' || b < '0' || b > '9' {
		return 0, false
	}
	return int(a-'0')*10 + int(b-'0'), true
}
