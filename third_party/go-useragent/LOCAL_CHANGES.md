# Local memory optimization

Upstream: `github.com/medama-io/go-useragent` v1.2.3. The upstream license,
runtime sources, normalized `data/final.txt` corpus and tests are retained.
Raw corpus-generation inputs are omitted; production does not use them.

- Freeze the constructed rune trie into a compact radix trie. Chains with no
  results and one child are edge labels; branch/result nodes use 32-bit offsets
  into pointer-free node, edge, label and result arrays.
- Preserve the original parser state machine, rune skipping, precedence and
  browser-version extraction. `go generate` derives the specialized traversal
  from `RuneTrie.Get`, which remains the uncompressed reference implementation.
- The public `Trie.Put` expands the representation on explicit mutation. Normal
  parser use keeps only compact arrays; no mutable construction graph is retained.
- Oversized inputs fall back to the reference representation rather than wrapping
  compact indexes. Memory-statistics APIs account for the compact representation.

Verification (run inside this directory):

```sh
go generate ./...
go test -race ./...
go test -run '^TestCompact' -bench '^BenchmarkTrieRepresentation$' -benchmem
```

Differential tests cover all normalized corpus entries, upstream expected-output
cases, version/Android suffixes, Unicode, malformed bytes, random input and
post-compaction mutation. `TestCompactStorage` checks the retained arrays.
