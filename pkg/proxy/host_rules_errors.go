package proxy

import (
	"errors"
	"log"
	"reflect"

	"go-reauth-proxy/pkg/config"
	"go-reauth-proxy/pkg/logger"
	"go-reauth-proxy/pkg/models"
)

// hostRulesPersistenceError distinguishes a valid host-rules bundle that
// could not be committed from a bundle rejected by validation. Control-plane
// callers can safely retry the former without retrying malformed input.
type hostRulesPersistenceError struct {
	err error
}

func (e *hostRulesPersistenceError) Error() string {
	return "persist host rules: " + e.err.Error()
}

func (e *hostRulesPersistenceError) Unwrap() error {
	return e.err
}

// IsHostRulesPersistenceError reports whether a host-rules update passed
// validation but failed while committing the gateway configuration.
func IsHostRulesPersistenceError(err error) bool {
	var persistenceErr *hostRulesPersistenceError
	return errors.As(err, &persistenceErr)
}

func hostRulesConfigurationEqual(
	currentRules []models.HostRule,
	nextRules []models.HostRule,
	currentPolicies map[string]models.CompiledIPSet,
	nextPolicies map[string]models.CompiledIPSet,
) bool {
	if len(currentRules) != len(nextRules) {
		return false
	}
	if len(currentRules) > 0 && !reflect.DeepEqual(
		copyHostRulesForPersistence(currentRules),
		copyHostRulesForPersistence(nextRules),
	) {
		return false
	}
	return reflect.DeepEqual(
		copyVisibilityPolicies(currentPolicies),
		copyVisibilityPolicies(nextPolicies),
	)
}

// persistHostRulesLocked saves only a candidate host-rule set while the caller
// holds h.mu. Keeping this update narrowly scoped avoids persisting unrelated
// runtime fields whose own save may previously have failed. Callers publish the
// candidate to requestState only after this returns nil.
func (h *Handler) persistHostRulesLocked(hostRules []models.HostRule) error {
	return h.persistHostRulesAndPoliciesLocked(hostRules, h.VisibilityPolicies)
}

func (h *Handler) persistHostRulesAndPoliciesLocked(
	hostRules []models.HostRule,
	policies map[string]models.CompiledIPSet,
) error {
	if h.configManager == nil {
		return nil
	}
	hostRulesCopy := copyHostRulesForPersistence(hostRules)
	policiesCopy := copyVisibilityPolicies(policies)
	if err := h.configManager.Update(func(conf *config.AppConfig) error {
		conf.HostRules = hostRulesCopy
		conf.VisibilityPolicies = policiesCopy
		return nil
	}); err != nil {
		if event := debugProxyEvent("host_rules_save_failed", ""); event != nil {
			event.Str("error", logger.SanitizeLogString(err.Error())).Send()
		}
		log.Printf("Failed to save host rules: %v", err)
		return &hostRulesPersistenceError{err: err}
	}
	if event := debugProxyEvent("host_rules_saved", ""); event != nil {
		event.Int("host_rule_count", len(hostRulesCopy)).Send()
	}
	return nil
}
