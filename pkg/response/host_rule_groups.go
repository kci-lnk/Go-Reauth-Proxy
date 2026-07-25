package response

import (
	"strings"

	"go-reauth-proxy/pkg/models"
)

type hostRuleGroupView struct {
	ID    string
	Name  string
	Rules []models.HostRule
}

func buildHostRuleGroupViews(rules []models.HostRule, ungroupedLabel string) ([]hostRuleGroupView, bool) {
	hasEffectiveGroups := false
	for _, rule := range rules {
		if strings.TrimSpace(rule.GroupID) != "" && strings.TrimSpace(rule.GroupName) != "" {
			hasEffectiveGroups = true
			break
		}
	}
	if !hasEffectiveGroups {
		return nil, false
	}

	groups := make([]hostRuleGroupView, 0)
	indexes := make(map[string]int)
	ungrouped := make([]models.HostRule, 0)
	for _, rule := range rules {
		id := strings.TrimSpace(rule.GroupID)
		name := strings.TrimSpace(rule.GroupName)
		if id == "" || name == "" {
			ungrouped = append(ungrouped, rule)
			continue
		}
		index, ok := indexes[id]
		if !ok {
			index = len(groups)
			indexes[id] = index
			groups = append(groups, hostRuleGroupView{ID: id, Name: name})
		}
		groups[index].Rules = append(groups[index].Rules, rule)
	}
	if len(ungrouped) > 0 {
		groups = append(groups, hostRuleGroupView{
			ID:    "",
			Name:  ungroupedLabel,
			Rules: ungrouped,
		})
	}
	return groups, true
}
