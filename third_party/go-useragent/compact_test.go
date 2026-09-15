package useragent

import (
	"bufio"
	"math/rand"
	"strings"
	"testing"
	"unsafe"

	"github.com/medama-io/go-useragent/data"
)

func referenceTrie() *RuneTrie {
	t := NewRuneTrie()
	s := bufio.NewScanner(strings.NewReader(userAgentsFile))
	for s.Scan() {
		t.Put(s.Text())
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
	return t
}

func TestCompactEquivalent(t *testing.T) {
	reference, packed := referenceTrie(), referenceTrie()
	packed.freeze()
	if packed.compact == nil || packed.childrenArr != nil || packed.result != nil {
		t.Fatal("builder graph was not released")
	}
	check := func(input string) {
		t.Helper()
		if got, want := packed.Get(input), reference.Get(input); got != want {
			t.Fatalf("different parse for %q: %+v != %+v", input, got, want)
		}
	}
	for _, tc := range data.AllTestCases {
		check(tc.UserAgent)
	}
	for _, input := range strings.Split(userAgentsFile, "\n") {
		check(input)
		check(input + "/123.45 (x; Android 13; Mobile/xyz)")
	}
	r := rand.New(rand.NewSource(27))
	alphabet := []byte("MozillaAndroidMobileChromeFirefoxSafariWindowsLinux0123/.;() -_\x00\xff")
	for i := 0; i < 5000; i++ {
		input := make([]byte, r.Intn(256))
		for j := range input {
			input[j] = alphabet[r.Intn(len(alphabet))]
		}
		check(string(input))
	}
	// Public Trie mutation still behaves as it did before compaction.
	for _, input := range []string{"MozillaFirefox", "MozillaAndroidMobile", "新浏览器MozillaSafari"} {
		reference.Put(input)
		packed.Put(input)
		check(input + "/123.4 ")
		packed.freeze()
		check(input + "/123.4 ")
	}
}

func TestCompactStorage(t *testing.T) {
	trie := referenceTrie()
	var before int
	var walk func(*RuneTrie)
	walk = func(n *RuneTrie) {
		before += int(unsafe.Sizeof(*n)) + cap(n.childrenArr)*int(unsafe.Sizeof(childNode{})) + cap(n.result)*int(unsafe.Sizeof(resultItem{}))
		for _, edge := range n.childrenArr {
			walk(edge.node)
		}
	}
	walk(trie)
	trie.freeze()
	after := trie.compact.memoryStats().TotalSize
	if stats := trie.GetTotalMemoryStats(); stats.TotalMemoryBytes != int64(after) || stats.NodeCount != int64(len(trie.compact.nodes)) {
		t.Fatalf("inconsistent compact memory statistics: %+v", stats)
	}
	t.Logf("trie storage: %d -> %d bytes; %d nodes", before, after, len(trie.compact.nodes))
	if after >= before/2 {
		t.Fatal("compact trie did not halve structural storage")
	}
}

func TestCompactCustomTries(t *testing.T) {
	r := rand.New(rand.NewSource(83))
	for trial := 0; trial < 100; trial++ {
		reference, packed := NewRuneTrie(), NewRuneTrie()
		inputs := []string{"", "a", "ab", "abcdef", "abcXdef", "中文浏览器", "MozillaFirefox/123.4 ", "Android Mobile Chrome "}
		for i := 0; i < 20; i++ {
			input := make([]byte, r.Intn(80))
			for j := range input {
				input[j] = byte(r.Intn(256))
			}
			inputs = append(inputs, string(input))
		}
		// Also cover an empty trie and freezing again after each public mutation.
		for _, input := range inputs {
			packed.freeze()
			for _, query := range inputs {
				if got, want := packed.Get(query), reference.Get(query); got != want {
					t.Fatalf("trial %d query %q differs", trial, query)
				}
			}
			reference.Put(input)
			packed.Put(input)
		}
	}
}

func FuzzCompactEquivalent(f *testing.F) {
	reference, packed := referenceTrie(), referenceTrie()
	packed.freeze()
	for _, tc := range data.AllTestCases {
		f.Add(tc.UserAgent)
	}
	f.Add("")
	f.Add("\x00\xff中文")
	f.Fuzz(func(t *testing.T, input string) {
		if got, want := packed.Get(input), reference.Get(input); got != want {
			t.Fatalf("different parse for %q: %+v != %+v", input, got, want)
		}
	})
}

var compactBenchmarkResult UserAgent

func BenchmarkTrieRepresentation(b *testing.B) {
	for _, mode := range []string{"reference", "compact"} {
		b.Run(mode, func(b *testing.B) {
			trie := referenceTrie()
			if mode == "compact" {
				trie.freeze()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				compactBenchmarkResult = trie.Get(data.AllTestCases[i%len(data.AllTestCases)].UserAgent)
			}
		})
	}
}
