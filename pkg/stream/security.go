package stream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	compiledipset "go-reauth-proxy/pkg/ipset"
	"go-reauth-proxy/pkg/models"
	"go-reauth-proxy/pkg/streamprobe"
)

const (
	streamValidationTimeout = 2 * time.Second
	streamValidationLimit   = 64 * 1024
)

type streamValidationFailure struct {
	decision string
	detected string
	evidence string
	err      error
}

func (failure *streamValidationFailure) Error() string {
	if failure == nil || failure.err == nil {
		return "stream validation failed"
	}
	return failure.err.Error()
}

func (failure *streamValidationFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.err
}

func copyCompiledPolicies(values map[string]models.CompiledIPSet) map[string]models.CompiledIPSet {
	copied := make(map[string]models.CompiledIPSet, len(values))
	for id, policy := range values {
		policy.IPv4Ranges = append(models.Base64URLBytes(nil), policy.IPv4Ranges...)
		policy.IPv6Ranges = append(models.Base64URLBytes(nil), policy.IPv6Ranges...)
		copied[id] = policy
	}
	return copied
}

func decodeStreamAccessPolicies(values map[string]models.CompiledIPSet) (map[string]models.CompiledIPSet, map[string]*compiledipset.Set, error) {
	policies := make(map[string]models.CompiledIPSet, len(values))
	sets := make(map[string]*compiledipset.Set, len(values))
	for rawID, rawPolicy := range values {
		id := strings.TrimSpace(rawID)
		policy := rawPolicy
		policy.ID = strings.TrimSpace(policy.ID)
		if policy.ID == "" {
			policy.ID = id
		}
		if id == "" || id != policy.ID {
			return nil, nil, fmt.Errorf("compiled stream policy key %q does not match id %q", rawID, policy.ID)
		}
		set, err := compiledipset.Decode(policy)
		if err != nil {
			return nil, nil, fmt.Errorf("decode stream policy %s: %w", id, err)
		}
		policy.IPv4Ranges = append(models.Base64URLBytes(nil), policy.IPv4Ranges...)
		policy.IPv6Ranges = append(models.Base64URLBytes(nil), policy.IPv6Ranges...)
		policies[id] = policy
		sets[id] = set
	}
	return policies, sets, nil
}

func (m *Manager) SetAccessPolicies(values map[string]models.CompiledIPSet) error {
	policies, sets, err := decodeStreamAccessPolicies(values)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("stream manager is closed")
	}
	m.accessPolicies = policies
	m.compiledAccessPolicies = sets
	m.ruleSnapshot.Store(&streamRuleSnapshot{
		rules:                  m.rules,
		availability:           models.CopyDailyAvailability(m.availability),
		accessPolicies:         policies,
		compiledAccessPolicies: sets,
	})
	return nil
}

func (m *Manager) matchStreamBypass(rule models.StreamRule, clientIP string) (bool, string) {
	if !rule.UseAuth || !rule.BypassPolicy.Enabled {
		return false, ""
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil || !addr.IsValid() {
		// An invalid address must never make a negative condition true.
		return false, ""
	}
	snapshot := m.ruleSnapshot.Load()
	if snapshot == nil {
		return false, ""
	}
	for _, group := range rule.BypassPolicy.Groups {
		matched := len(group.Conditions) > 0
		for _, condition := range group.Conditions {
			set := snapshot.compiledAccessPolicies[strings.TrimSpace(condition.PolicyID)]
			if set == nil {
				matched = false
				break
			}
			contains := set.Contains(addr)
			switch strings.ToLower(strings.TrimSpace(condition.Operator)) {
			case "equals", "in", "in_cidr":
				matched = matched && contains
			case "not_equals", "not_in", "not_in_cidr":
				matched = matched && !contains
			default:
				matched = false
			}
			if !matched {
				break
			}
		}
		if matched {
			return true, group.ID
		}
	}
	return false, ""
}

func validateTCPInitial(conn net.Conn, serviceID, direction string) ([]byte, string, string, error) {
	if conn == nil {
		return nil, "", "", &streamValidationFailure{decision: "internal", err: errors.New("connection is nil")}
	}
	if err := conn.SetReadDeadline(time.Now().Add(streamValidationTimeout)); err != nil {
		return nil, "", "", &streamValidationFailure{decision: "internal", err: err}
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	buffer := make([]byte, 0, 1024)
	chunk := make([]byte, 4096)
	for len(buffer) < streamValidationLimit {
		remaining := streamValidationLimit - len(buffer)
		if remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, err := conn.Read(chunk)
		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			state := streamprobe.Validate(serviceID, "tcp", direction, buffer)
			switch state {
			case streamprobe.ValidationMatch:
				classification := streamprobe.Classify("tcp", direction, buffer)
				return buffer, serviceID, classification.Evidence, nil
			case streamprobe.ValidationProbable:
				return nil, serviceID, "probable_only", &streamValidationFailure{
					decision: "ambiguous", detected: serviceID, evidence: "probable_only",
					err: errors.New("protocol signature is only probable"),
				}
			case streamprobe.ValidationMismatch:
				classification := streamprobe.Classify("tcp", direction, buffer)
				detected := classification.ServiceID
				return nil, detected, classification.Evidence, &streamValidationFailure{
					decision: "mismatch", detected: detected, evidence: classification.Evidence,
					err: fmt.Errorf("expected %s protocol preface", serviceID),
				}
			}
		}
		if err != nil {
			decision := "read_error"
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				decision = "timeout"
			} else if errors.Is(err, io.EOF) {
				decision = "truncated"
			}
			return nil, "", "", &streamValidationFailure{decision: decision, err: err}
		}
	}
	return nil, "", "", &streamValidationFailure{decision: "response_too_large", err: errors.New("protocol preface exceeds 64 KiB")}
}

func writeInitial(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		written, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func (s *udpSession) firstQueuedPayload() []byte {
	if s == nil {
		return nil
	}
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.queueLen == 0 {
		return nil
	}
	payload := s.queue[s.queueHead].payload
	return append([]byte(nil), payload...)
}

func validateUDPInitial(rule models.StreamRule, payload []byte) (string, string, error) {
	state := streamprobe.Validate(rule.ServiceProfile.ServiceID, "udp", streamprobe.DirectionClient, payload)
	classification := streamprobe.Classify("udp", streamprobe.DirectionClient, payload)
	switch state {
	case streamprobe.ValidationMatch:
		return rule.ServiceProfile.ServiceID, classification.Evidence, nil
	case streamprobe.ValidationProbable:
		return classification.ServiceID, classification.Evidence, &streamValidationFailure{
			decision: "ambiguous", detected: classification.ServiceID, evidence: classification.Evidence,
			err: errors.New("UDP protocol signature is only probable"),
		}
	case streamprobe.ValidationNeedMore:
		return classification.ServiceID, classification.Evidence, &streamValidationFailure{
			decision: "truncated", detected: classification.ServiceID, evidence: classification.Evidence,
			err: errors.New("UDP protocol handshake is incomplete"),
		}
	default:
		return classification.ServiceID, classification.Evidence, &streamValidationFailure{
			decision: "mismatch", detected: classification.ServiceID, evidence: classification.Evidence,
			err: fmt.Errorf("expected %s UDP handshake", rule.ServiceProfile.ServiceID),
		}
	}
}
