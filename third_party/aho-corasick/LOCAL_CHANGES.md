# Local memory optimization

Upstream: `github.com/petar-dambovaliev/aho-corasick`
`v0.0.0-20250424160509-463d218d4745`. Upstream sources, tests and license retained.

- Keep upstream NFA/DFA construction and the search algorithms in `automaton.go`.
- Freeze completed NFAs into pointer-free state, sparse-transition, dense-table
  and ordered-match arrays. State/transition offsets use bounded 32-bit indexes.
  Construction-only depth, per-node pointers and spare slice capacity are absent
  from the runtime representation. Inputs exceeding index bounds retain the
  original NFA instead of truncating indexes.
- Keep failure links, dense lookup, sparse transition order, case behavior,
  longest/first/standard selection, overlapping matches and capture order intact.
- DFA construction is unchanged; its temporary NFA is not compacted.

Verification (run inside this directory):

```sh
go test -race ./...
go test -run '^TestCompact' -bench '^BenchmarkNFARepresentation$' -benchmem
```

Differential tests compare against the original NFA across all matching modes,
case/whole-word options, random dictionaries, duplicate patterns, Unicode,
malformed bytes and overlapping matches. Transition tests compare every byte
at every state for a representative dictionary.
