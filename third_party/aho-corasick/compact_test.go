package aho_corasick

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func uncompactMatcher(options Opts, patterns []string) AhoCorasick {
	bytes := make([][]byte, len(patterns))
	for i, p := range patterns {
		bytes[i] = []byte(p)
	}
	b := NewAhoCorasickBuilder(options)
	n := b.nfaBuilder.build(bytes)
	return AhoCorasick{n, n.matchKind, options.MatchOnlyWholeWords}
}

func compactMatches(it Iter) []Match {
	var result []Match
	for m := it.Next(); m != nil; m = it.Next() {
		result = append(result, *m)
	}
	return result
}

func TestCompactEquivalent(t *testing.T) {
	r := rand.New(rand.NewSource(41))
	for _, kind := range []matchKind{StandardMatch, LeftMostFirstMatch, LeftMostLongestMatch} {
		for _, insensitive := range []bool{false, true} {
			for _, words := range []bool{false, true} {
				for trial := 0; trial < 60; trial++ {
					patterns := []string{"a", "ab", "abc", "Ab", "ab", "中文", "\x00\xff"}
					for i := 0; i < 20; i++ {
						p := make([]byte, 1+r.Intn(12))
						for j := range p {
							p[j] = "abABc ."[r.Intn(7)]
						}
						patterns = append(patterns, string(p))
					}
					options := Opts{MatchKind: kind, AsciiCaseInsensitive: insensitive, MatchOnlyWholeWords: words}
					reference := uncompactMatcher(options, patterns)
					builder := NewAhoCorasickBuilder(options)
					packed := builder.Build(patterns)
					haystack := "\x00\xff ab ABC 中文 " + strings.Join(patterns, " abc ")
					if got, want := packed.FindAll(haystack), reference.FindAll(haystack); !reflect.DeepEqual(got, want) {
						t.Fatalf("matches differ: kind=%d insensitive=%v words=%v trial=%d", kind, insensitive, words, trial)
					}
					if kind == StandardMatch {
						got, want := compactMatches(packed.IterOverlapping(haystack)), compactMatches(reference.IterOverlapping(haystack))
						if !reflect.DeepEqual(got, want) {
							t.Fatal("overlapping matches differ")
						}
					}
				}
			}
		}
	}
}

func TestCompactTransitionsUnchanged(t *testing.T) {
	options := Opts{MatchKind: LeftMostLongestMatch, AsciiCaseInsensitive: true}
	patterns := []string{"a", "ab", "abc", "bcd", "cde", "中文", "\x00\xff"}
	n := uncompactMatcher(options, patterns).i.(*iNFA)
	before := make([][]stateID, len(n.states))
	for i := range n.states {
		before[i] = make([]stateID, 256)
		for b := 0; b < 256; b++ {
			before[i][b] = n.states[i].nextState(byte(b))
		}
	}
	p := n.compact().(*packedNFA)
	for i, s := range p.states {
		for b, want := range before[i] {
			if got := p.nextState(&s, byte(b)); got != want {
				t.Fatalf("state %d byte %d: %d != %d", i, b, got, want)
			}
		}
	}
}

func TestCompactEmptyAndPrefixPatterns(t *testing.T) {
	for _, patterns := range [][]string{nil, {""}, {"", "a", ""}, {"a", "aa", "aaa", "a"}, {"\x00", "\xff", "中文"}} {
		for _, kind := range []matchKind{StandardMatch, LeftMostFirstMatch, LeftMostLongestMatch} {
			for _, words := range []bool{false, true} {
				options := Opts{MatchKind: kind, MatchOnlyWholeWords: words}
				reference := uncompactMatcher(options, patterns)
				builder := NewAhoCorasickBuilder(options)
				packed := builder.Build(patterns)
				for _, input := range []string{"", "a", "aaaa", " a ", "\x00\xff中文"} {
					if got, want := packed.FindAll(input), reference.FindAll(input); !reflect.DeepEqual(got, want) {
						t.Fatalf("patterns %q input %q kind %d words %v: %v != %v", patterns, input, kind, words, got, want)
					}
				}
			}
		}
	}
}

var compactBenchmarkMatches []Match

func TestCompactStorage(t *testing.T) {
	var patterns []string
	for i := 0; i < 1000; i++ {
		patterns = append(patterns, fmt.Sprintf("keyword-%04d-long-suffix", i))
	}
	n := uncompactMatcher(Opts{MatchKind: LeftMostLongestMatch, AsciiCaseInsensitive: true}, patterns).i.(*iNFA)
	before := cap(n.states) * int(unsafe.Sizeof(state{}))
	for _, s := range n.states {
		before += cap(s.matches) * int(unsafe.Sizeof(pattern{}))
		if s.trans.sparse != nil {
			before += int(unsafe.Sizeof(sparse{})) + cap(s.trans.sparse.inner)*int(unsafe.Sizeof(innerSparse{}))
		} else {
			before += int(unsafe.Sizeof(dense{})) + cap(s.trans.dense.inner)*int(unsafe.Sizeof(stateID(0)))
		}
	}
	p := n.compact().(*packedNFA)
	after := cap(p.states)*int(unsafe.Sizeof(packedState{})) + cap(p.edges)*int(unsafe.Sizeof(packedTransition{})) + cap(p.dense)*4 + cap(p.matches)*int(unsafe.Sizeof(pattern{}))
	t.Logf("NFA structural storage: %d -> %d bytes, %d states", before, after, len(p.states))
	if after >= before*3/4 {
		t.Fatal("packed NFA did not reduce structural storage by at least 25%")
	}
}

func BenchmarkNFARepresentation(b *testing.B) {
	patterns := []string{"select", "union", "../", "<script", "javascript:", "cmd.exe"}
	for i := 0; i < 1000; i++ {
		patterns = append(patterns, fmt.Sprintf("keyword-%04d-long-suffix", i))
	}
	options := Opts{MatchKind: LeftMostLongestMatch, AsciiCaseInsensitive: true}
	for _, mode := range []string{"reference", "compact"} {
		for _, input := range []struct{ name, text string }{
			{"miss", strings.Repeat("normal request data ", 128)},
			{"hits", strings.Repeat("SELECT union <script keyword-0523-long-suffix ", 16)},
		} {
			b.Run(mode+"/"+input.name, func(b *testing.B) {
				matcher := uncompactMatcher(options, patterns)
				if mode == "compact" {
					matcher.i = matcher.i.(*iNFA).compact()
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(input.text)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					compactBenchmarkMatches = matcher.FindAll(input.text)
				}
			})
		}
	}
}
