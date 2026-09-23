# Final Go authentication hot-path evidence — 2026-09-23

The final product source is **4d15fa32764e26df58b16930d0e2503a90880002**, compared directly with original baseline **92d4c0cb5495d57801d52893a8f0e8496a1c9182**. It includes the five allocation optimizations, the pre-existing late trace-trailer fix, and two Cookie compatibility fixes found during independent review. This documentation does not change the product source identity.

These final local measurements supersede the earlier local headline results for `91f65cc` and `748c97e`. The earlier experiment directories and their raw results remain unchanged as historical stages. No percentages below are compounded from those stages.

## Final six-pair local benchmark

The original baseline and final candidate use the same lean handler fixture, Go 1.26.7, darwin/arm64, Apple M5, and `-test.cpu=2`. Both binaries receive a 200 ms warmup; six pairs alternate AB/BA, with a 1 s measurement for each benchmark. All tests and compilation finished before the measured CPU window; no concurrent Rust build or other agent load ran locally.

| Lean host-route benchmark | Median ns/op baseline → final | Paired median time change | Paired bootstrap 95% | Median B/op baseline → final | Allocs/op baseline → final |
| --- | ---: | ---: | ---: | ---: | ---: |
| Authentication off | 4708 → 4367 | -7.190% | -7.545% to -6.563% | 6517 → 5350 | 66 → 55 |
| Combined authorization cache hit | 6999 → 5946.5 | -15.198% | -15.527% to -14.238% | 8336 → 6096 | 90 → 66 |

Paired median B/op changes are **-17.920%** and **-26.896%**. Paired changes are computed within each pair before taking their median; they can differ from the ratio of the two independent medians. Bootstrap intervals resample those six paired changes with 10,000 draws and a fixed seed. The repository benchmark checker passes with the latency regression limit tightened to 5%, retaining its default byte/allocation limits.

This measures local gateway handler CPU time and allocation, with parsing prepared outside the loop and a simulated upstream transport. It does not measure Linux service throughput, peak RSS, SQLite concurrency, or end-to-end authentication latency. Matched Linux artifacts require their own formal A/B and soak validation.

`results/` contains every warmup and measured invocation, combined role outputs, exact samples, medians, intervals, binary hashes, environment metadata and checker output. Baseline binary SHA-256 is `d6d65aff189616316a174b350d4f787cd21eef40e5bf9434905e0fd119b1b513`; the unchanged fixture SHA-256 is `449dc0b1d6ab764da8c3cea7e190ea48d01f3b14f857950c27b348dab54b639d`. The original baseline binary was reused from the prior experiment after builder confirmation, fixture comparison, and comparison of all 406 archived production Go source blobs with `92d4c0c`; hashes and final build information are in `validation/`.

## Cookie compatibility corrections

The ordinary-cookie fast path introduced in `91f65cc` preserved all raw text when no reserved grant was present. Two cases changed what a Go upstream could parse:

- Empty segments: `sid=ok` followed by 3000 semicolons, semicolon/spaces, or semicolon/tabs. The old helper removed empty segments, leaving one cookie. Raw passthrough exceeded Go's default raw-segment limit, causing `Request.Cookies()` to return no cookies. Commit `0978d6b03767c3e5f3ebf72fa13074c2b72afe7d` restored normalization for empty segments.
- Non-HTTP boundary whitespace: `sid=ok\u00a0`, `\u00a0sid=ok`, or mixed SP/HT and Unicode spaces. The old `strings.TrimSpace` removed these characters, while the upstream parser trims only HTTP SP/HT. Commit `4d15fa3` restores that behavior, including VT/FF in directly constructed helper inputs.

The final scanner creates the SP/HT-trimmed segment view, then enters the existing normalization/filtering path if it is empty or if `strings.TrimSpace` would further shorten it. Ordinary segments still return without allocations. The product code does not hardcode a Cookie-count limit or enumerate Unicode whitespace characters. Reserved grant name matching and its existing malformed-input filtering path remain intact.

`cookie-limit-repro.go.txt` is a minimal standalone reproduction using the real Go `http.Request.Cookies` parser. Its raw output is in `validation/cookie-limit-repro.log`. The same 17-case production-helper regression suite was applied as a **test-only overlay** to archived sources: original `92d4c0c` passes, intermediate `748c97e` fails, final `4d15fa3` passes. All three outcomes are recorded. The expected intermediate failure is retained, not counted as a final test failure.

## Correctness checks and review scope

Final-source commands all exit 0; full logs and command identities are in `validation/`:

```sh
go test ./pkg/proxy -run '^TestStripAdvancedAuthGrant' -count=1
go test ./...
go test -race ./pkg/proxy
go vet ./...
```

Existing ordinary Cookie and Set-Cookie tests still verify zero allocations and byte preservation for the fast path. Grant filtering covers mixed-case and malformed fields. The late-trailer regression covers 24 real HTTP/1 and HTTP/2 upstream/downstream combinations, announced and dynamic ordinary/trace trailers, and plain/SSE/binary streaming before EOF. WebSocket, proxy-error and stream tests remain included in the full and race runs.

Read-only review against `92d4c0c` found no further changed authorization semantics in these areas:

- Published cache entries clone the Cookie slice and allowed-host map. Current production readers do not mutate them; replacement/invalidation removes cache references without recycling the objects held by in-flight requests. Preflight decisions contain only value fields.
- Exact-request cache entries still precede host-scope entries. Binary digests use unchanged hash fields: identity and its access-token/user-agent augmentation, client IP, access mode, scheme, effective host, route identity and advanced-auth policy version. Exact verification also includes method and request URI; preflight retains matched status and URI. Host scope intentionally omits method/URI as before. Logout identity strings remain hexadecimal.
- ASCII trace-header matching retains the Unicode lowercase fallback and existing `Trailer:` classification. The separate late-trailer fix filters after ReverseProxy copies EOF trailers and before net/http finishes the response, without changing body Reader/Closer or upgrade interfaces.

These are bounded source-review and test conclusions, not a proof about all possible callers or malformed protocols.

## Reproduction

From the Go repository root with the pinned Go toolchain available:

```sh
bench_work=$(mktemp -d)
mkdir "$bench_work/baseline" "$bench_work/final"
git archive 92d4c0cb5495d57801d52893a8f0e8496a1c9182 | tar -xf - -C "$bench_work/baseline"
git archive 4d15fa32764e26df58b16930d0e2503a90880002 | tar -xf - -C "$bench_work/final"
git show 4d15fa32764e26df58b16930d0e2503a90880002:pkg/proxy/hot_path_benchmark_test.go \
  > "$bench_work/baseline/pkg/proxy/hot_path_benchmark_test.go"
(cd "$bench_work/baseline" && go test -c -o "$bench_work/baseline.test" ./pkg/proxy)
(cd "$bench_work/final" && go test -c -o "$bench_work/final.test" ./pkg/proxy)
python3 docs/experiments/trace-trailer-fix-20260923/run-benchmarks.py \
  --comparison final \
  --before-binary "$bench_work/baseline.test" \
  --after-binary "$bench_work/final.test" \
  --output "$bench_work/results"
go run ./tools/benchcheck \
  --base "$bench_work/results/before.txt" \
  --current "$bench_work/results/after.txt" \
  --max-latency-regression 0.05
```

Run measurements with local builds and competing load stopped. The runner refuses an existing output directory. Python only orchestrates native Go benchmarks. To run the standalone Cookie reproduction, copy `cookie-limit-repro.go.txt` to a temporary `.go` file and execute `go run` on that file. No test binaries, databases or secret-bearing runtime data are archived here.
