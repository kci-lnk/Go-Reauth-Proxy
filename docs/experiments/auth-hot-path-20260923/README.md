# Authentication hot-path allocation experiment — 2026-09-23

The candidate reduces gateway-only host-route allocations by 17.92% with authentication off and 26.90% with a combined authorization cache hit. Both median latency and allocations per operation improve. Keep all five changes; the write-heavy cache case spends 16 more bytes per operation (+4.55%) while its latency improves and allocation count stays unchanged.

The product binary identity is **91f65ccd9eae6441cd02abb064cf83f10c1a5c84**, version **2.4.15**. This documentation commit does not change that binary and does not require rebuilding it. Baseline: **92d4c0cb5495d57801d52893a8f0e8496a1c9182**.

## Measurement and reproduction

Measured on Apple M5, macOS, Go 1.26.7 darwin/arm64, `-test.cpu=2`, with other local compilation and load paused. Primary benchmarks use 500 ms per sample; original end-to-end and stage benchmarks use 300 ms. Every comparison has six complete samples. Baseline/candidate order alternates; stage order alternates forward/reverse. Both primary variants receive a 200 ms warm-up.

The original request fixture calls `httptest.NewRequest` inside the measured loop. A preceding allocation profile attributed 31.6% of allocations to its `bufio.NewReader`. The added `BenchmarkHandlerHotPath*` fixture prepares parsing outside the loop, but still clones request, URL and headers and uses a fresh response writer. The exact same benchmark source is compiled against the baseline and candidate. It checks response status/body length and checks that timed cache hits perform no authorization RPC. Original fixtures are also retained as independent end-to-end and stage checks.

Run from a quiet machine with Go 1.26.7 and this repository's commit history available:

```sh
python3 docs/experiments/auth-hot-path-20260923/run-benchmarks.py --output /tmp/auth-hot-path-rerun
```

The script builds isolated archived sources at every pinned SHA, adds only the shared benchmark fixture, runs all samples sequentially, writes metadata/raw output/medians, and applies the repository's benchmark gate. Output must be a new directory. It does not change the checkout. Runtime improvements on this ARM Mac are not a claim about production Linux latency; matched Linux product artifacts are supplied for the separate system A/B experiment.

## Primary results

Values are six-sample medians, ordered as baseline → candidate.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| Host route, auth off, gateway fixture | 4691 → 4253.5 (-9.33%) | 6517 → 5349 (-17.92%) | 66 → 55 |
| Host route, combined cache hit, gateway fixture | 6940.5 → 5839.5 (-15.86%) | 8335 → 6093 (-26.90%) | 90 → 66 |
| Combined cache-key construction | 697.6 → 610.55 (-12.48%) | 256 → 64 | 4 → 1 |
| High-cardinality cache writes | 265.4 → 230.55 (-13.13%) | 352 → 368 (+4.55%) | 3 → 3 |
| Parallel high-cardinality cache writes | 419.45 → 369.65 (-11.87%) | 352 → 368 (+4.55%) | 3 → 3 |
| Ordinary cookie, one value | 130.7 → 38.695 | 48 → 0 | 3 → 0 |
| Ordinary cookies, eight values | 333.7 → 106.8 | 416 → 0 | 5 → 0 |
| Ordinary cookies, 32 values | 958.1 → 350.05 | 1536 → 0 | 5 → 0 |
| Five trace-header classifications | 307.05 → 94.76 | 128 → 0 | 10 → 0 |

The 13 original end-to-end scenarios pass the existing latency/bytes/allocation gate. Cache-hit 1 KiB latency changes 44.294 → 42.514 μs and B/op changes 19090 → 16804 (-11.97%). Combined miss latency changes 48.539 → 47.252 μs. WAF, portal injection, request logging and parallel cases remain covered.

Three large-response median latency changes are slightly positive: serial 2 MiB +0.89%, parallel 2 MiB +2.28%, unknown-length parallel 2 MiB +0.52%. An additional gate with zero latency tolerance yields bootstrap 95% intervals of [-5.0%, +7.4%], [-4.7%, +4.3%], and [-2.8%, +3.8%]. There is no statistically supported regression in these samples; this is not proof that every workload has zero regression.

## Independent changes

Stage columns use the unchanged original isolated host-hit fixture, including request-parser overhead.

| Commit | Change | Host hit ns/op | Host hit B/op | Host hit allocs/op |
|---|---|---:|---:|---:|
| `92d4c0c` | Baseline | 7879.5 | 13071.5 | 99 |
| `0cc5ef5` | Compact reverse-proxy closure captures | 7597.5 | 11997.5 | 96 |
| `eb08cbb` | Lazy protobuf context and separate cache-miss callbacks | 7311.5 | 11461 | 90 |
| `894d112` | Immutable published cache entries | 7140 | 11167.5 | 89 |
| `2a54d30` | Binary request/host digests; identity format preserved | 7113.5 | 10973.5 | 86 |
| `91f65cc` | Ordinary-cookie and ASCII-header fast paths | 6688 | 10832.5 | 75 |

`4725c86` moves combined authorization into `http_auth_combined.go` to preserve the existing source-file size budget; it has no intended behavior change. All stage raw samples are included in `raw/*-isolated.txt`.

Published auth entries clone cookie slices and allowed-host maps and are never recycled after invalidation. Exact-request entries still precede host entries. Binary digests preserve their previous hash inputs; logout and active-session identity strings remain hexadecimal. Lazy protobuf materialization retains optional-field presence, including explicitly empty routed fields, upgrade metadata and legacy header fallback. Reserved/malformed grant-cookie stripping retains its original slow path; ordinary cookies remain byte-for-byte unchanged. Trace stripping retains trailer behavior and a Unicode fallback.

## Validation and artifacts

Completed successfully:

- `go test ./...`
- `go test -race ./pkg/proxy`
- `go vet ./...`
- Both default `tools/benchcheck` comparisons, plus end-to-end `--max-latency-regression=0`.

New tests exercise concurrent lazy materialization, unused protobuf on a complete hit, invalidation/replacement while a reader holds an old immutable entry, caller slice/map isolation, exact-before-host ordering, ordinary and reserved/malformed cookies, and trace/trailer classification parity. Existing tests cover optional fields, cancellation, logout, FN App behavior, routing and gateway response handling.

`raw/` contains every sample and gate output. `summary.json`, `summary-e2e.json`, and `summary-stages.json` retain exact medians. `validation/` contains the full functional/race/vet logs (the successful vet log is empty).

Linux amd64 artifacts were built with `CGO_ENABLED=0`, `-trimpath`, and `-ldflags '-s -w -X go-reauth-proxy/pkg/version.Version=2.4.15 -X go-reauth-proxy/pkg/version.Commit=<SHA>'`:

- Baseline: `/tmp/fn-knock-auth-artifacts-20260923/base/go-reauth-proxy`.
- Candidate: `/tmp/fn-knock-auth-artifacts-20260923/candidate/go-reauth-proxy`; SHA-256 `84df34e6125bdc31b7f53cca575a6d21578830b4eb20de87a1ec5e517de75562`.

The artifacts are local experiment outputs, not production deployments. Existing snapshot/routing, pooled copy buffers, keepalive limits and backpressure-driven coalescing were retained; this experiment does not retune them or replace `httputil.ReverseProxy`.
