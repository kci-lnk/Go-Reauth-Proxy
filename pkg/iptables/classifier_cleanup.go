package iptables

import (
	"fmt"
	"strings"
)

// Query only our chains, not the entire filter table (which may contain native
// nft expressions from other applications). Missing chains are expected on a
// first installation; permission and other inspection failures must propagate.
func (m *Manager) chainRulesIfExists(table, chain string) (string, bool, error) {
	output, err := m.runTableOutput(table, "-S", chain)
	if err == nil {
		return output, true, nil
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "permission denied") && !strings.Contains(message, "operation not permitted") &&
		(strings.Contains(message, "no chain/target/match by that name") ||
			(strings.Contains(message, "chain") && strings.Contains(message, "does not exist"))) {
		return "", false, nil
	}
	return "", false, err
}

// Use descending rule numbers to avoid parsing the unavailable mark extension
// during deletion, while preserving every unrelated rule and its order.
func writeJumpRemovals(builder *strings.Builder, rules, parent, target string) {
	var indexes []int
	index := 0
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != parent {
			continue
		}
		index++
		if firewallRuleJumpsTo(line, parent, target) {
			indexes = append(indexes, index)
		}
	}
	for i := len(indexes) - 1; i >= 0; i-- {
		fmt.Fprintf(builder, "-D %s %d\n", parent, indexes[i])
	}
}

// iptables -S quotes comments and escapes their contents. Only tokens outside
// those quotes can be options: a comment containing "-j FNK-WL-MARK" must not
// make an unrelated rule look like one of our classifier consumers.
func firewallRuleJumpsTo(line, parent, target string) bool {
	first, rest, ok := nextQuotedRuleField(line)
	if !ok || first != "-A" {
		return false
	}
	second, rest, ok := nextQuotedRuleField(rest)
	if !ok || second != parent {
		return false
	}
	for {
		field, remaining, ok := nextQuotedRuleField(rest)
		if !ok {
			return false
		}
		rest = remaining
		if field == "--comment" {
			_, rest, _ = nextQuotedRuleField(rest)
			continue
		}
		if field == "-j" {
			jump, _, ok := nextQuotedRuleField(rest)
			return ok && jump == target
		}
	}
}

// Keep tokens verbatim, including quotes, so a quoted option name is never
// interpreted as syntax. Deletion reuses the original rule text as well.
func nextQuotedRuleField(line string) (field, rest string, ok bool) {
	line = strings.TrimLeft(line, " \t\r\n")
	if line == "" {
		return "", "", false
	}
	var quote byte
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == '\\':
			i++
		case quote != 0:
			if line[i] == quote {
				quote = 0
			}
		case line[i] == '"' || line[i] == '\'':
			quote = line[i]
		case isASCIISpace(line[i]):
			return line[:i], line[i:], true
		}
	}
	if quote != 0 {
		return "", "", false
	}
	return line, "", true
}

func (m *Manager) writeWhitelistClassifierRemoval(table string, builder *strings.Builder) error {
	rules, _, err := m.chainRulesIfExists(table, m.Chain)
	if err != nil {
		return err
	}
	writeJumpRemovals(builder, rules, m.Chain, whitelistMarkChainName)
	_, exists, err := m.chainRulesIfExists(table, whitelistMarkChainName)
	if err != nil {
		return err
	}
	if exists {
		fmt.Fprintf(builder, "-F %s\n-X %s\n", whitelistMarkChainName, whitelistMarkChainName)
	}
	return nil
}

// Init/Flush replace the base rules themselves. Clean up classifiers only after
// those consumers are gone; preserve an already synchronized direct whitelist.
func (m *Manager) cleanupLegacyWhitelistClassifier() error {
	classified, err := m.nftClassificationEnabled()
	if err != nil || classified {
		return err
	}
	m.whitelistPolicyMu.Lock()
	defer m.whitelistPolicyMu.Unlock()
	for _, table := range m.tables {
		var builder strings.Builder
		builder.WriteString("*filter\n")
		if err := m.writeWhitelistClassifierRemoval(table, &builder); err != nil {
			return err
		}
		if builder.Len() > len("*filter\n") {
			builder.WriteString("COMMIT\n")
			if err := m.runTableRestore(table, builder.String()); err != nil {
				return err
			}
		}
	}
	m.whitelistNftReady = false
	return m.clearNftTable(whitelistNftTableName)
}

func (m *Manager) removeUnusedChain(table, chain string) error {
	_, exists, err := m.chainRulesIfExists(table, chain)
	if err != nil || !exists {
		return err
	}
	// If a remaining reference prevents deletion, roll back the flush too.
	// Otherwise a failed cleanup could empty a still-live enforcement chain.
	return m.runTableRestore(table, fmt.Sprintf("*filter\n-F %s\n-X %s\nCOMMIT\n", chain, chain))
}
