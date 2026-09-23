# Late trace trailer regression fix

This is the historical `748c97e` endpoint. The [final Go report](../auth-final-20260923/README.md) records the later Cookie compatibility fixes and a new direct `92d4c0c` → `4d15fa3` six-pair comparison. All measurements below remain the original archived stage results.

A new authenticated business-proxy wire test exposed an existing leak: `ModifyResponse` filtered the initial trailer map, but Go's transport filled it again at body EOF. ReverseProxy then copied the newly populated trace trailers downstream. The affected forwarding and response-writer files had no changes between the performance baseline `92d4c0c` and optimized `91f65cc`; this is a previously uncovered correctness defect, not an optimization benefit.

The test-only reproduction is `0f16a93b15555afbbd2c6ac7f4c813debb2290b1`. It failed for `X-Fn-Knock-Trace-ID`, `Traceparent`, `B3`, `X-B3-SpanId`, and an unannounced `X-Custom-Trace-Token`; ordinary Digest and X-Checksum trailers were preserved. The production fix is `748c97e03f6fb9087ac0b3c90064611dc2c6cf66`.

The fix filters the downstream header map after ReverseProxy returns and after the existing coalescer stops its timer. At that point ReverseProxy has closed the body and copied both announced and `Trailer:`-prefixed dynamic trailers, while net/http has not yet sent the final trailers. There is no body wrapper, extra body buffering, Read/Close interception, or change to upgrade handling. Existing initial-header filtering remains in place.

## Validation

`TestAuthenticatedBusinessProxyPreservesOrdinaryTrailersWithoutTraceLeakOnWire` passes all 24 combinations: upstream HTTP/1 or HTTP/2, downstream HTTP/1 or HTTP/2, announced or dynamic trailers, and plain text, SSE, or binary content. Both hops use actual HTTP servers/transports; the authorization bridge is mocked and checked for exactly one successful session authorization. Each test requires the client to read the first body chunk while the upstream is held before EOF, then verifies ordinary Digest, X-Checksum and dynamic X-Late-Checksum trailers and absence of five trace fields.

Commands all exited 0 after the production fix:

```sh
go test ./pkg/proxy -run '^TestAuthenticatedBusinessProxyPreservesOrdinaryTrailersWithoutTraceLeakOnWire$' -count=1
go test ./...
go test -race ./pkg/proxy
go vet ./...
```

Full test/race/vet logs are in `validation/`; the empty vet log denotes no diagnostics. Existing WebSocket real-network tests, response-copy error paths and streaming tests are included in the full and race proxy runs. This fix does not change Reader or Closer semantics.

## Local lean benchmark

The same two lean handler benchmarks were compiled before and after the fix, then run without concurrent builds or tests on Apple M5 / darwin arm64 / Go 1.26.7. Each binary received a 200 ms warmup; six pairs alternated AB/BA with `-test.cpu=2`, `-test.benchtime=1s`, and `-test.benchmem`. Positive ns/op changes mean overhead. Bootstrap intervals resample six paired relative changes, take the median, and use 10,000 draws with a fixed seed.

| Benchmark | Before median ns/op | After median ns/op | Paired median change | Paired bootstrap 95% | Allocations before → after |
| --- | ---: | ---: | ---: | ---: | ---: |
| AuthOff | 4316.5 | 4400.5 | +1.966% | +1.188% to +3.284% | 55 → 55 |
| CacheHit | 5894.0 | 5945.5 | +0.806% | -0.542% to +2.190% | 66 → 66 |

Median bytes/op were 5351 → 5352 and 6096.5 → 6099. The repository benchmark checker passed with the latency regression limit tightened to 5%; its default byte/allocation limits were retained. These results measure the incremental correctness fix against the already optimized code. They are local microbenchmarks, not Linux service throughput or RSS evidence, and do not supersede the final matched-artifact remote tests.

Raw per-pair output, combined role output, binary hashes, metadata, paired samples, intervals and the checker result are in `results/`. No binaries or runtime secrets are archived.

## Original baseline to final candidate

A separate six-pair run directly compares original `92d4c0cb5495d57801d52893a8f0e8496a1c9182` against final `748c97e03f6fb9087ac0b3c90064611dc2c6cf66`, including the trailer fix. It uses the same shared benchmark fixture, platform, quiet CPU window, warmup and AB/BA parameters described above. Its percentages are measured directly and are not compounded from earlier experiment stages.

| Benchmark | Before median ns/op | Final median ns/op | Paired median change | Paired bootstrap 95% | Median B/op before → final | Allocs/op before → final |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AuthOff | 4719.5 | 4406 | -6.725% | -7.561% to -5.696% | 6519.5 → 5351.5 | 66 → 55 |
| CacheHit | 7013 | 5983.5 | -14.558% | -15.409% to -14.095% | 8337.5 → 6092.5 | 90 → 66 |

Paired median B/op changes are -17.892% and -26.927%. The repository checker passed with the 5% latency regression limit. `overall-results/` contains all raw samples, metadata, summaries and checker output. These are final local hot-path results; they retain the Linux/service/RSS limitations above.

The original baseline test binary was reused from the earlier hot-path experiment, with its builder confirming its identity. All 406 production Go source files in its archived source directory match the `92d4c0c` Git blobs, and its added lean fixture matches the final fixture byte-for-byte. The binary and fixture hashes were recorded for this run in `validation/baseline-provenance.json` and the run metadata. Historical binary-hash evidence is not claimed.

## Reproduction

Build the two pinned revisions into temporary directories. `hot_path_benchmark_test.go` is identical at both revisions.

```sh
bench_work=$(mktemp -d)
mkdir "$bench_work/before" "$bench_work/after"
git archive 0f16a93b15555afbbd2c6ac7f4c813debb2290b1 | tar -xf - -C "$bench_work/before"
git archive 748c97e03f6fb9087ac0b3c90064611dc2c6cf66 | tar -xf - -C "$bench_work/after"
(cd "$bench_work/before" && go test -c -o "$bench_work/before.test" ./pkg/proxy)
(cd "$bench_work/after" && go test -c -o "$bench_work/after.test" ./pkg/proxy)
python3 docs/experiments/trace-trailer-fix-20260923/run-benchmarks.py \
  --before-binary "$bench_work/before.test" \
  --after-binary "$bench_work/after.test" \
  --output "$bench_work/results"
go run ./tools/benchcheck \
  --base "$bench_work/results/before.txt" \
  --current "$bench_work/results/after.txt" \
  --max-latency-regression 0.05
```

The runner refuses an existing output directory. Keep the machine free of concurrent compilation or other CPU load during measurements. Python only orchestrates the native Go benchmark binaries; it does not generate HTTP load.

For the direct original-to-final comparison, reuse the final binary built above and build the original production sources with the identical measurement-only fixture:

```sh
mkdir "$bench_work/original"
git archive 92d4c0cb5495d57801d52893a8f0e8496a1c9182 | tar -xf - -C "$bench_work/original"
git show 748c97e03f6fb9087ac0b3c90064611dc2c6cf66:pkg/proxy/hot_path_benchmark_test.go \
  > "$bench_work/original/pkg/proxy/hot_path_benchmark_test.go"
(cd "$bench_work/original" && go test -c -o "$bench_work/original.test" ./pkg/proxy)
python3 docs/experiments/trace-trailer-fix-20260923/run-benchmarks.py \
  --comparison overall \
  --before-binary "$bench_work/original.test" \
  --after-binary "$bench_work/after.test" \
  --output "$bench_work/overall-results"
go run ./tools/benchcheck \
  --base "$bench_work/overall-results/before.txt" \
  --current "$bench_work/overall-results/after.txt" \
  --max-latency-regression 0.05
```
