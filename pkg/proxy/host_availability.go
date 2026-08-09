package proxy

import (
	"go-reauth-proxy/pkg/models"
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
	return models.NormalizeDailyAvailability(value)
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

	if models.DailyAvailabilityOpenAt(availability, now) {
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
	return models.FormatDailyAvailabilityWindow(value)
}
