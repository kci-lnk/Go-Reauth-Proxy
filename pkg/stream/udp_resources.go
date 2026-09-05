package stream

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"go-reauth-proxy/pkg/diagnostics"
)

var errUDPBufferBudgetExhausted = errors.New("UDP buffer budget exhausted")

// Read once at process startup. A zero budget preserves existing admission
// limits; constrained deployments can opt into a shared live-buffer cap.
var processUDPBufferBudget = &udpBufferBudget{limit: udpResourceEnv("FN_KNOCK_UDP_BUFFER_BUDGET_BYTES", 0, 0, 1<<62)}
var configuredUDPIdleTimeout = time.Duration(udpResourceEnv("FN_KNOCK_UDP_SESSION_IDLE_SECONDS", 120, 1, 86400)) * time.Second

type udpBufferBudget struct {
	limit int64
	used  atomic.Int64
}

func udpResourceEnv(name string, fallback, minimum, maximum int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		log.Printf("Invalid %s; using default %d", name, fallback)
		return fallback
	}
	return value
}

func udpPacketCapacity(size int) int {
	for _, capacity := range [...]int{udpSmallPacketBufferSize, udpMediumPacketBufferSize, udp16KPacketBufferSize, udp32KPacketBufferSize, udpLargePacketBufferSize} {
		if size <= capacity {
			return capacity
		}
	}
	return size
}

func acquireUDPPacketWithBudget(size int, budget *udpBufferBudget) (udpPacket, bool) {
	// A disabled budget must not add a global atomic hot spot to every packet.
	// Only explicitly budgeted packets carry a reservation to their release.
	if budget == nil || budget.limit <= 0 {
		return acquireUDPPacket(size), true
	}
	capacity := int64(udpPacketCapacity(size))
	for {
		current := budget.used.Load()
		if capacity > budget.limit || current > budget.limit-capacity {
			diagnostics.RecordUDPBufferBudgetDrop()
			return udpPacket{}, false
		}
		if budget.used.CompareAndSwap(current, current+capacity) {
			packet := acquireUDPPacket(size)
			packet.budget = budget
			return packet, true
		}
	}
}
