package ipset

import (
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/netip"
	"os"
	"testing"
)

func TestCompileMergesEquivalentIPv4AndIPv6Ranges(t *testing.T) {
	compiled, err := Compile([]string{
		"192.0.2.128/25",
		"192.0.2.0/25",
		"192.0.2.0/24",
		"2001:db8::/127",
		"2001:db8::2/127",
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if got := set.RangeCount(); got != 2 {
		t.Fatalf("range count = %d, want 2", got)
	}
	for _, value := range []string{"192.0.2.0", "192.0.2.255", "2001:db8::", "2001:db8::3"} {
		if !set.Contains(netip.MustParseAddr(value)) {
			t.Fatalf("compiled set did not contain %s", value)
		}
	}
	for _, value := range []string{"192.0.3.0", "2001:db8::4"} {
		if set.Contains(netip.MustParseAddr(value)) {
			t.Fatalf("compiled set unexpectedly contained %s", value)
		}
	}
}

func TestCompilePolicyIDIsDeterministicForEquivalentSets(t *testing.T) {
	left, err := Compile([]string{"192.0.2.0/25", "192.0.2.128/25"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Compile([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if left.ID != right.ID {
		t.Fatalf("equivalent IDs differ: %s != %s", left.ID, right.ID)
	}
}

func TestCompileFullAddressSpacesWithoutOverflow(t *testing.T) {
	compiled, err := Compile([]string{"0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	set, err := Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if !set.Contains(netip.MustParseAddr(value)) {
			t.Fatalf("full set did not contain %s", value)
		}
	}
}

func TestCompileMatchesCrossLanguageGoldenFixture(t *testing.T) {
	var fixture struct {
		CIDRs         []string `json:"cidrs"`
		ID            string   `json:"id"`
		FormatVersion uint32   `json:"format_version"`
		IPv4Ranges    string   `json:"ipv4_ranges"`
		IPv6Ranges    string   `json:"ipv6_ranges"`
	}
	raw, err := os.ReadFile("testdata/ipset-v1-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(fixture.CIDRs)
	if err != nil {
		t.Fatal(err)
	}
	if compiled.ID != fixture.ID || compiled.FormatVersion != fixture.FormatVersion {
		t.Fatalf("compiled identity = (%s, %d), want (%s, %d)", compiled.ID, compiled.FormatVersion, fixture.ID, fixture.FormatVersion)
	}
	if base64.RawURLEncoding.EncodeToString(compiled.IPv4Ranges) != fixture.IPv4Ranges {
		t.Fatal("compiled IPv4 bytes differ from golden fixture")
	}
	if base64.RawURLEncoding.EncodeToString(compiled.IPv6Ranges) != fixture.IPv6Ranges {
		t.Fatal("compiled IPv6 bytes differ from golden fixture")
	}
}

func TestCompiledLookupMatchesPrefixScanForBoundariesAndRandomAddresses(t *testing.T) {
	cidrs := []string{
		"0.0.0.0/32",
		"10.0.0.0/8",
		"192.0.2.0/24",
		"255.255.255.255/32",
		"::/128",
		"2001:db8::/32",
		"fe80::/10",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, value := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	compiled, err := Compile(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	set, err := Decode(compiled)
	if err != nil {
		t.Fatal(err)
	}
	assertEquivalent := func(addr netip.Addr) {
		t.Helper()
		legacy := false
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				legacy = true
				break
			}
		}
		if got := set.Contains(addr); got != legacy {
			t.Fatalf("contains(%s) = %t, prefix scan = %t", addr, got, legacy)
		}
	}
	for _, value := range []string{
		"0.0.0.0", "0.0.0.1", "9.255.255.255", "10.0.0.0", "10.255.255.255",
		"11.0.0.0", "192.0.1.255", "192.0.2.0", "192.0.2.255", "192.0.3.0",
		"255.255.255.254", "255.255.255.255", "::", "::1", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
		"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::",
		"fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"fec0::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		assertEquivalent(netip.MustParseAddr(value))
	}
	random := rand.New(rand.NewSource(0xF17C1D))
	for range 100_000 {
		if random.Intn(2) == 0 {
			assertEquivalent(netip.AddrFrom4([4]byte{
				byte(random.Uint32()),
				byte(random.Uint32()),
				byte(random.Uint32()),
				byte(random.Uint32()),
			}))
			continue
		}
		var value [16]byte
		_, _ = random.Read(value[:])
		assertEquivalent(netip.AddrFrom16(value))
	}
}
