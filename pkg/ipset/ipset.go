package ipset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"go-reauth-proxy/pkg/models"
)

const FormatVersion uint32 = 1

var digestDomain = []byte("fnknock-ipset-v1\x00")

type range4 struct {
	start uint32
	end   uint32
}

type range6 struct {
	start [16]byte
	end   [16]byte
}

// Set is an exact immutable address set backed by sorted, disjoint ranges.
type Set struct {
	ID   string
	ipv4 []range4
	ipv6 []range6
}

func Compile(cidrs []string) (models.CompiledIPSet, error) {
	v4 := make([]range4, 0, len(cidrs))
	v6 := make([]range6, 0, len(cidrs))
	for _, raw := range cidrs {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return models.CompiledIPSet{}, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4() {
			startBytes := prefix.Addr().As4()
			start := binary.BigEndian.Uint32(startBytes[:])
			hostBits := 32 - prefix.Bits()
			end := uint32(^uint32(0))
			if hostBits < 32 {
				end = start | (uint32(1)<<hostBits - 1)
			}
			v4 = append(v4, range4{start: start, end: end})
			continue
		}
		start := prefix.Addr().As16()
		end := start
		setHostBits(&end, prefix.Bits())
		v6 = append(v6, range6{start: start, end: end})
	}
	v4 = merge4(v4)
	v6 = merge6(v6)
	ipv4Ranges := make([]byte, 0, len(v4)*8)
	for _, item := range v4 {
		ipv4Ranges = binary.BigEndian.AppendUint32(ipv4Ranges, item.start)
		ipv4Ranges = binary.BigEndian.AppendUint32(ipv4Ranges, item.end)
	}
	ipv6Ranges := make([]byte, 0, len(v6)*32)
	for _, item := range v6 {
		ipv6Ranges = append(ipv6Ranges, item.start[:]...)
		ipv6Ranges = append(ipv6Ranges, item.end[:]...)
	}
	return models.CompiledIPSet{
		ID:            policyID(ipv4Ranges, ipv6Ranges),
		FormatVersion: FormatVersion,
		IPv4Ranges:    ipv4Ranges,
		IPv6Ranges:    ipv6Ranges,
	}, nil
}

func Decode(policy models.CompiledIPSet) (*Set, error) {
	if policy.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("unsupported compiled IP set format version %d", policy.FormatVersion)
	}
	if len(policy.IPv4Ranges)%8 != 0 {
		return nil, fmt.Errorf("compiled IPv4 range length %d is invalid", len(policy.IPv4Ranges))
	}
	if len(policy.IPv6Ranges)%32 != 0 {
		return nil, fmt.Errorf("compiled IPv6 range length %d is invalid", len(policy.IPv6Ranges))
	}
	expectedID := policyID(policy.IPv4Ranges, policy.IPv6Ranges)
	if strings.TrimSpace(policy.ID) != expectedID {
		return nil, fmt.Errorf("compiled IP set digest mismatch: expected %s, got %s", expectedID, policy.ID)
	}
	set := &Set{
		ID:   expectedID,
		ipv4: make([]range4, 0, len(policy.IPv4Ranges)/8),
		ipv6: make([]range6, 0, len(policy.IPv6Ranges)/32),
	}
	for offset := 0; offset < len(policy.IPv4Ranges); offset += 8 {
		item := range4{
			start: binary.BigEndian.Uint32(policy.IPv4Ranges[offset : offset+4]),
			end:   binary.BigEndian.Uint32(policy.IPv4Ranges[offset+4 : offset+8]),
		}
		if item.start > item.end || (len(set.ipv4) > 0 && set.ipv4[len(set.ipv4)-1].end >= item.start) {
			return nil, fmt.Errorf("compiled IPv4 ranges are not sorted and disjoint")
		}
		set.ipv4 = append(set.ipv4, item)
	}
	for offset := 0; offset < len(policy.IPv6Ranges); offset += 32 {
		var item range6
		copy(item.start[:], policy.IPv6Ranges[offset:offset+16])
		copy(item.end[:], policy.IPv6Ranges[offset+16:offset+32])
		if compare16(item.start, item.end) > 0 ||
			(len(set.ipv6) > 0 && compare16(set.ipv6[len(set.ipv6)-1].end, item.start) >= 0) {
			return nil, fmt.Errorf("compiled IPv6 ranges are not sorted and disjoint")
		}
		set.ipv6 = append(set.ipv6, item)
	}
	return set, nil
}

func (set *Set) Contains(addr netip.Addr) bool {
	if set == nil || !addr.IsValid() {
		return false
	}
	if addr.Is4() {
		valueBytes := addr.As4()
		value := binary.BigEndian.Uint32(valueBytes[:])
		index := sort.Search(len(set.ipv4), func(i int) bool {
			return set.ipv4[i].end >= value
		})
		return index < len(set.ipv4) && set.ipv4[index].start <= value
	}
	value := addr.As16()
	index := sort.Search(len(set.ipv6), func(i int) bool {
		return compare16(set.ipv6[i].end, value) >= 0
	})
	return index < len(set.ipv6) && compare16(set.ipv6[index].start, value) <= 0
}

func (set *Set) RangeCount() int {
	if set == nil {
		return 0
	}
	return len(set.ipv4) + len(set.ipv6)
}

func policyID(ipv4Ranges, ipv6Ranges []byte) string {
	hasher := sha256.New()
	_, _ = hasher.Write(digestDomain)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(ipv4Ranges)/8))
	_, _ = hasher.Write(count[:])
	_, _ = hasher.Write(ipv4Ranges)
	binary.BigEndian.PutUint32(count[:], uint32(len(ipv6Ranges)/32))
	_, _ = hasher.Write(count[:])
	_, _ = hasher.Write(ipv6Ranges)
	return "ipset-v1:" + hex.EncodeToString(hasher.Sum(nil))
}

func setHostBits(value *[16]byte, prefixBits int) {
	for bit := prefixBits; bit < 128; bit++ {
		value[bit/8] |= 1 << (7 - uint(bit%8))
	}
}

func merge4(values []range4) []range4 {
	sort.Slice(values, func(i, j int) bool {
		if values[i].start == values[j].start {
			return values[i].end < values[j].end
		}
		return values[i].start < values[j].start
	})
	merged := make([]range4, 0, len(values))
	for _, value := range values {
		if len(merged) == 0 {
			merged = append(merged, value)
			continue
		}
		last := &merged[len(merged)-1]
		adjacent := last.end != ^uint32(0) && value.start == last.end+1
		if value.start <= last.end || adjacent {
			if value.end > last.end {
				last.end = value.end
			}
			continue
		}
		merged = append(merged, value)
	}
	return merged
}

func merge6(values []range6) []range6 {
	sort.Slice(values, func(i, j int) bool {
		if comparison := compare16(values[i].start, values[j].start); comparison != 0 {
			return comparison < 0
		}
		return compare16(values[i].end, values[j].end) < 0
	})
	merged := make([]range6, 0, len(values))
	for _, value := range values {
		if len(merged) == 0 {
			merged = append(merged, value)
			continue
		}
		last := &merged[len(merged)-1]
		adjacent := increment16(last.end)
		if compare16(value.start, last.end) <= 0 ||
			(adjacent != nil && compare16(value.start, *adjacent) <= 0) {
			if compare16(value.end, last.end) > 0 {
				last.end = value.end
			}
			continue
		}
		merged = append(merged, value)
	}
	return merged
}

func increment16(value [16]byte) *[16]byte {
	next := value
	for index := len(next) - 1; index >= 0; index-- {
		next[index]++
		if next[index] != 0 {
			return &next
		}
	}
	return nil
}

func compare16(left, right [16]byte) int {
	return bytes.Compare(left[:], right[:])
}
