package iptables

import "strings"

// multiport has 15 slots; an inclusive start:end range consumes two.
// Share this calculation with baseRuleCountForTable so dynamically inserted
// rules stay before the terminal DROP even when exemption ranges are present.
func exemptPortChunks(ports []string) [][]string {
	var chunks [][]string
	start, slots := 0, 0
	for i, port := range ports {
		cost := 1
		if strings.Contains(port, ":") {
			cost = 2
		}
		if slots+cost > 15 {
			chunks = append(chunks, ports[start:i])
			start, slots = i, 0
		}
		slots += cost
	}
	if start < len(ports) {
		chunks = append(chunks, ports[start:])
	}
	return chunks
}
