package ipset

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"sort"
	"strings"

	"go-reauth-proxy/pkg/models"
)

const (
	LegacyFormatVersion    uint32 = 1
	FormatVersion          uint32 = 2
	maxCanonicalRangeBytes        = 64 * 1024 * 1024
)

var (
	v1DigestDomain = []byte("fnknock-ipset-v1\x00")
	v2DigestDomain = []byte("fnknock-ipset-v2\x00")
)

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

// Resolve validates a compiled policy or compiles deprecated CIDR input. The
// returned policy owns its byte slices and can be safely stored in an immutable
// runtime snapshot.
func Resolve(policyID string, policy *models.CompiledIPSet, legacyCIDRs []string) (models.CompiledIPSet, *Set, error) {
	policyID = strings.TrimSpace(policyID)
	var compiled models.CompiledIPSet
	if policy != nil {
		compiled = Clone(*policy)
		if compiled.ID == "" {
			compiled.ID = policyID
		}
		if policyID != "" && compiled.ID != policyID {
			return models.CompiledIPSet{}, nil, fmt.Errorf(
				"compiled IP set reference mismatch: expected %s, got %s",
				policyID,
				compiled.ID,
			)
		}
	} else {
		if policyID != "" {
			return models.CompiledIPSet{}, nil, fmt.Errorf(
				"compiled IP set %s is referenced but missing",
				policyID,
			)
		}
		var err error
		compiled, err = Compile(legacyCIDRs)
		if err != nil {
			return models.CompiledIPSet{}, nil, err
		}
	}
	set, err := Decode(compiled)
	if err != nil {
		return models.CompiledIPSet{}, nil, err
	}
	return compiled, set, nil
}

func Clone(policy models.CompiledIPSet) models.CompiledIPSet {
	return models.CompiledIPSet{
		ID:            policy.ID,
		FormatVersion: policy.FormatVersion,
		IPv4Ranges:    append(models.Base64URLBytes(nil), policy.IPv4Ranges...),
		IPv6Ranges:    append(models.Base64URLBytes(nil), policy.IPv6Ranges...),
	}
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
		ID:            policyID(FormatVersion, ipv4Ranges, ipv6Ranges),
		FormatVersion: FormatVersion,
		IPv4Ranges:    compressRanges(ipv4Ranges),
		IPv6Ranges:    compressRanges(ipv6Ranges),
	}, nil
}

func Decode(policy models.CompiledIPSet) (*Set, error) {
	var ipv4Ranges, ipv6Ranges []byte
	var err error
	switch policy.FormatVersion {
	case LegacyFormatVersion:
		ipv4Ranges = policy.IPv4Ranges
		ipv6Ranges = policy.IPv6Ranges
	case FormatVersion:
		ipv4Ranges, err = decompressRanges(policy.IPv4Ranges, "IPv4")
		if err != nil {
			return nil, err
		}
		ipv6Ranges, err = decompressRanges(policy.IPv6Ranges, "IPv6")
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported compiled IP set format version %d", policy.FormatVersion)
	}
	if len(ipv4Ranges)%8 != 0 {
		return nil, fmt.Errorf("compiled IPv4 range length %d is invalid", len(ipv4Ranges))
	}
	if len(ipv6Ranges)%32 != 0 {
		return nil, fmt.Errorf("compiled IPv6 range length %d is invalid", len(ipv6Ranges))
	}
	expectedID := policyID(policy.FormatVersion, ipv4Ranges, ipv6Ranges)
	if strings.TrimSpace(policy.ID) != expectedID {
		return nil, fmt.Errorf("compiled IP set digest mismatch: expected %s, got %s", expectedID, policy.ID)
	}
	set := &Set{
		ID:   expectedID,
		ipv4: make([]range4, 0, len(ipv4Ranges)/8),
		ipv6: make([]range6, 0, len(ipv6Ranges)/32),
	}
	for offset := 0; offset < len(ipv4Ranges); offset += 8 {
		item := range4{
			start: binary.BigEndian.Uint32(ipv4Ranges[offset : offset+4]),
			end:   binary.BigEndian.Uint32(ipv4Ranges[offset+4 : offset+8]),
		}
		if item.start > item.end ||
			(len(set.ipv4) > 0 && ranges4Touch(set.ipv4[len(set.ipv4)-1], item)) {
			return nil, fmt.Errorf("compiled IPv4 ranges are not sorted, disjoint, and non-adjacent")
		}
		set.ipv4 = append(set.ipv4, item)
	}
	for offset := 0; offset < len(ipv6Ranges); offset += 32 {
		var item range6
		copy(item.start[:], ipv6Ranges[offset:offset+16])
		copy(item.end[:], ipv6Ranges[offset+16:offset+32])
		var touchesPrevious bool
		if len(set.ipv6) > 0 {
			previous := set.ipv6[len(set.ipv6)-1]
			next := increment16(previous.end)
			touchesPrevious = compare16(previous.end, item.start) >= 0 ||
				(next != nil && compare16(*next, item.start) >= 0)
		}
		if compare16(item.start, item.end) > 0 ||
			touchesPrevious {
			return nil, fmt.Errorf("compiled IPv6 ranges are not sorted, disjoint, and non-adjacent")
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

// Prefixes returns the smallest exact CIDR cover for the canonical ranges.
// It is intended for control-plane consumers such as kernel firewall loaders,
// never for request-time membership checks.
func (set *Set) Prefixes() []string {
	if set == nil {
		return nil
	}
	prefixes := make([]string, 0, set.RangeCount())
	for _, item := range set.ipv4 {
		start := item.start
		for {
			alignmentBits := bits.TrailingZeros32(start)
			remaining := uint64(item.end) - uint64(start) + 1
			hostBits := min(alignmentBits, bits.Len64(remaining)-1)
			address := [4]byte{
				byte(start >> 24),
				byte(start >> 16),
				byte(start >> 8),
				byte(start),
			}
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(address), 32-hostBits).String())
			if hostBits == 32 {
				break
			}
			next := uint64(start) + 1<<hostBits
			if next > uint64(item.end) {
				break
			}
			start = uint32(next)
		}
	}
	for _, item := range set.ipv6 {
		start := item.start
		for {
			hostBits := trailingZeroBits16(start)
			for hostBits > 0 {
				blockEnd := start
				setHostBits(&blockEnd, 128-hostBits)
				if compare16(blockEnd, item.end) <= 0 {
					break
				}
				hostBits--
			}
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(start), 128-hostBits).String())
			blockEnd := start
			setHostBits(&blockEnd, 128-hostBits)
			if compare16(blockEnd, item.end) == 0 {
				break
			}
			next := increment16(blockEnd)
			if next == nil {
				break
			}
			start = *next
		}
	}
	return prefixes
}

func trailingZeroBits16(value [16]byte) int {
	total := 0
	for index := len(value) - 1; index >= 0; index-- {
		if value[index] == 0 {
			total += 8
			continue
		}
		return total + bits.TrailingZeros8(value[index])
	}
	return 128
}

func policyID(formatVersion uint32, ipv4Ranges, ipv6Ranges []byte) string {
	var domain []byte
	var prefix string
	switch formatVersion {
	case LegacyFormatVersion:
		domain = v1DigestDomain
		prefix = "ipset-v1:"
	case FormatVersion:
		domain = v2DigestDomain
		prefix = "ipset-v2:"
	default:
		panic(fmt.Sprintf("policy ID requested for unsupported format %d", formatVersion))
	}
	hasher := sha256.New()
	_, _ = hasher.Write(domain)
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(ipv4Ranges)/8))
	_, _ = hasher.Write(count[:])
	_, _ = hasher.Write(ipv4Ranges)
	binary.BigEndian.PutUint32(count[:], uint32(len(ipv6Ranges)/32))
	_, _ = hasher.Write(count[:])
	_, _ = hasher.Write(ipv6Ranges)
	return prefix + hex.EncodeToString(hasher.Sum(nil))
}

func compressRanges(ranges []byte) []byte {
	if len(ranges) == 0 {
		return nil
	}
	var encoded bytes.Buffer
	writer, err := zlib.NewWriterLevel(&encoded, zlib.BestCompression)
	if err != nil {
		panic(fmt.Sprintf("create zlib encoder: %v", err))
	}
	if _, err := writer.Write(ranges); err != nil {
		panic(fmt.Sprintf("compress compiled IP ranges: %v", err))
	}
	if err := writer.Close(); err != nil {
		panic(fmt.Sprintf("finish compressed IP ranges: %v", err))
	}
	return encoded.Bytes()
}

func decompressRanges(encoded []byte, family string) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	reader, err := zlib.NewReader(bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("compiled %s ranges are invalid zlib: %w", family, err)
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, maxCanonicalRangeBytes+1))
	if err != nil {
		return nil, fmt.Errorf("decompress compiled %s ranges: %w", family, err)
	}
	if len(decoded) > maxCanonicalRangeBytes {
		return nil, fmt.Errorf(
			"compiled %s ranges exceed the %d byte decompression limit",
			family,
			maxCanonicalRangeBytes,
		)
	}
	return decoded, nil
}

func ranges4Touch(previous, next range4) bool {
	return previous.end >= next.start ||
		(previous.end != ^uint32(0) && previous.end+1 >= next.start)
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
