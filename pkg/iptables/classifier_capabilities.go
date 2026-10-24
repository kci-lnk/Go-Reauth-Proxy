package iptables

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"go-reauth-proxy/pkg/logger"
)

// nftClassificationEnabled selects one mode for both families and both policy
// types. Keep nftCommand intact: fallback still needs it to remove old tables.
// Operational failures are not cached, so a later request can retry them.
func (m *Manager) nftClassificationEnabled() (bool, error) {
	m.classificationMu.Lock()
	defer m.classificationMu.Unlock()
	if m.classificationChecked {
		return m.classificationEnabled, nil
	}
	if m.isDisabled() || m.nftCommand == "" {
		return false, nil
	}
	var unavailable []string
	for _, table := range m.tables {
		reason, err := m.probeMarkExtensions(table)
		if err != nil {
			return false, err
		}
		if reason != "" {
			unavailable = append(unavailable, table+": "+reason)
		}
	}
	m.classificationEnabled = len(unavailable) == 0
	m.classificationChecked = true
	if !m.classificationEnabled {
		detail := logger.SanitizeLogString(strings.Join(unavailable, "; "))
		logger.Diagnostic("WARN", "iptables", "classifier_fallback", "mark_unavailable", map[string]any{
			"status": "legacy_per_source",
			"result": "Using per-source firewall rules; large policies may be slower. " + detail,
		})
		if event := logger.DebugEvent("iptables", "classifier_fallback"); event != nil {
			event.Str("reason", detail).
				Msg("Using per-source firewall rules; large policies may be slower")
		}
	}
	return m.classificationEnabled, nil
}

// Probe the actual kernel/userspace combination, not --help or the presence of
// nft. The temporary chain is never linked to a hook and cannot affect traffic.
// A cleanup error takes precedence over an otherwise recoverable missing MARK.
func (m *Manager) probeMarkExtensions(table string) (reason string, err error) {
	var suffix [6]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		return "", err
	}
	chain := fmt.Sprintf("FNK-PROBE-%x", suffix)
	if err = m.runTable(table, "-N", chain); err != nil {
		return "", err
	}
	defer func() {
		flushErr := m.runTable(table, "-F", chain)
		deleteErr := m.runTable(table, "-X", chain)
		if cleanupErr := errors.Join(flushErr, deleteErr); cleanupErr != nil {
			if reason != "" {
				err = errors.Join(err, errors.New(reason))
			}
			err = errors.Join(err, fmt.Errorf("clean up MARK probe %s (%s): %w", chain, table, cleanupErr))
		}
	}()
	for _, args := range [][]string{
		{"-A", chain, "-j", "MARK", "--set-xmark", "0x0/0x40000000"},
		{"-A", chain, "-m", "mark", "--mark", whitelistPacketMarkWithMask, "-j", "RETURN"},
	} {
		output, runErr := m.runner.CombinedOutput(table, args...)
		if runErr == nil {
			continue
		}
		failure := fmt.Errorf("%s %s: %w, output: %s", table, strings.Join(args, " "), runErr, output)
		if markExtensionUnavailable(string(output)) {
			return failure.Error(), nil
		}
		return "", failure
	}
	return "", nil
}

func markExtensionUnavailable(output string) bool {
	message := strings.ToLower(output)
	// Never turn an operational failure into a capability downgrade, even if
	// the command also printed an extension warning.
	for _, fatal := range []string{"permission denied", "operation not permitted", "resource temporarily unavailable", "xtables lock"} {
		if strings.Contains(message, fatal) {
			return false
		}
	}
	if strings.Contains(message, "unknown option") &&
		(strings.Contains(message, "--set-xmark") || strings.Contains(message, "--mark")) {
		return true
	}
	if strings.Contains(message, "extension mark") &&
		(strings.Contains(message, "not supported") || strings.Contains(message, "missing kernel module")) {
		return true
	}
	for _, kind := range []string{"match", "target"} {
		for _, verb := range []string{"couldn't load ", "could not load ", "can't load ", "cannot load "} {
			if strings.Contains(message, verb+kind) &&
				(strings.Contains(message, "`mark'") || strings.Contains(message, "'mark'") || strings.Contains(message, "\"mark\"")) &&
				strings.Contains(message, "no such file or directory") {
				return true
			}
		}
	}
	return false
}
