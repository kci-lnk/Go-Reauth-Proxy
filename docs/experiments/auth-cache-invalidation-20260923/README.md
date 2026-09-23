# Authentication cache invalidation repair — 2026-09-23

Product fix: **66998225a2d0d78e40390c179681b6a48b5e5635**, against **4d15fa32764e26df58b16930d0e2503a90880002**. The race also existed in the original `92d4c0c` baseline. The earlier final-performance evidence remains evidence for 4d15fa3; it does not represent this repaired product.

An authorization RPC could decide before logout, return after the gateway invalidated the session, and republish its old decision. A request beginning after invalidation could also join that earlier singleflight call. This repair prevents reuse by later requests. It does **not** retroactively revoke the result of an already in-flight request.

## Synchronization and scope

- A bounded global generation identifies authorization operations. Identity invalidation and full cache clear acquire auth then preflight locks, advance the generation, and delete the relevant entries before releasing either lock. There is no per-identity tombstone table.
- Misses include the generation in their singleflight key. Publication compares the captured generation under the same cache lock used by invalidation. Old calls may finish with their own result, including a denial, but cannot publish after invalidation or replace a newer decision.
- `snapshotForRequest` captures the generation **before** loading configuration. The returned snapshot value and production request auth context carry it through preflight, verify, combined fallbacks and delayed entry into authorization. An old configuration snapshot cannot adopt a generation created by a later TTL/configuration clear, including off/on changes that restore identical settings.
- Invalidating one identity conservatively suppresses all older pending fills, including unrelated identities. Existing entries belonging to other identities remain usable. Expiration, FIFO eviction and negative-cache bypass do not advance the generation. All relevant Set-Cookie paths still converge on the same invalidation helper; persisted authentication configuration changes still clear both caches.
- No mutable entry is recycled, no active singleflight Group is replaced, and no new authorization decision cache is introduced. Existing TTL/scope limits, exact-before-host order, optional protobuf presence and RPC timeout/cancellation behavior remain intact.

The extra steady-path work is an atomic generation load before the request snapshot and two value fields on the request auth context; direct internal authorization callers without a bound snapshot capture at entry. A miss singleflight digest is now 40 rather than 32 bytes. These costs and the conservative suppression of unrelated pending fills must be measured; correctness alone does not establish zero overhead.

## Deterministic regression evidence

`validation/baseline-barrier-overlay.go.txt` is the same first 80-case regression function from the repaired tree, compatible with the original API. On unchanged 4d15fa3 production source, **80/80 cases fail** (`before-final-80.log`). On the fix, all pass (`after-focused-final.log`). The channel barriers cover:

- Old allow and old denial; a fresh decision must survive a late old response.
- Legacy verify/preflight, combined verify-only/preflight-only, and full combined authorization.
- Identity invalidation, clear, logout Cookie deletion, and persisted TTL off/on configuration updates.
- Old response returning after invalidation, and a new request completing before the old response is released.

Additional tests cover old snapshot acquisition before a configuration clear but authorization entry afterward; retained unrelated cache hits; discarded pending fills; preserving original in-flight denials; and no epoch advance for expiration/eviction. The old-snapshot tests use the same snapshot/context binding as production; they do not claim an arbitrary old AuthConfig value passed without its request context can reveal its original generation.

Final-source commands exit 0:

```sh
go test ./pkg/proxy -run '^TestAuthCache(Invalidation|OldConfigurationSnapshot)' -count=1 -v
go test ./...
go test -race ./pkg/proxy
go vet ./...
```

The complete proxy race run took 13.267 s. Commands, input identities and logs are under `validation/`. The initial anonymous-fixture attempt is retained and explicitly superseded: it omitted LoginAuthenticated and therefore did not exercise positive cache publication. No production service, remote listener or external load is needed for these tests.

Reproduce the expected baseline failure in an isolated source archive:

```sh
experiment_root="$PWD/docs/experiments/auth-cache-invalidation-20260923"
regression_work=$(mktemp -d)
git archive 4d15fa32764e26df58b16930d0e2503a90880002 | tar -xf - -C "$regression_work"
cp "$experiment_root/validation/baseline-barrier-overlay.go.txt" \
  "$regression_work/pkg/proxy/auth_cache_invalidation_test.go"
(cd "$regression_work" && go test ./pkg/proxy \
  -run '^TestAuthCacheInvalidationSeparatesPendingAuthorization$' -count=1 -v)
```

This command is expected to exit nonzero with 80 failing subtests. The actual recorded run used Go's test-only overlay to substitute the same original files without editing the checkout; the overlay manifest is archived alongside the logs. No test data or benchmark history was rewritten.

## Local performance comparison

Both six-pair comparisons completed in one exclusive local CPU window after all Rust/Go compilation and functional tests had ended. They use the unchanged lean fixture, Go 1.26.7, darwin/arm64, Apple M5 and `-test.cpu=2`. Each binary receives 200 ms warmup; six 1 s samples per benchmark alternate AB/BA. `run-benchmarks.py` retains the prior fixed-seed 10,000-resample paired bootstrap; only declared source identities differ.

Incremental cost, **4d15fa3 → 6699822**:

| Benchmark | Median ns/op | Paired time change | Paired bootstrap 95% | Median B/op | Allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| Auth off | 4366 → 4348 | -0.147% | -3.320% to +1.404% | 5353 → 5350.5 | 55 → 55 |
| Cache hit | 5876.5 → 5931.5 | +0.870% | -0.024% to +1.343% | 6094.5 → 6109.5 | 66 → 66 |

The cache-hit byte increase is +0.262% paired (about 15 B/op); allocations are unchanged. The time interval crosses zero, so this is not evidence of a certain slowdown or literally zero overhead. The existing checker passes with its latency limit tightened to 5%, retaining the original byte/allocation limits. No miss/invalidation throughput claim is derived from this hit fixture.

Direct overall comparison, **92d4c0c → 6699822**:

| Benchmark | Median ns/op | Paired time change | Paired bootstrap 95% | Median B/op | Paired byte change | Allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Auth off | 4677.5 → 4379 | -6.396% | -7.243% to -5.384% | 6519.5 → 5352.5 | -17.894% | 66 → 55 |
| Cache hit | 6952.5 → 5926 | -14.953% | -17.876% to -14.220% | 8335.5 → 6111 | -26.665% | 90 → 66 |

This direct six-pair comparison also passes the tightened checker and retains allocation reductions above 10%. These are fresh measurements against the original baseline, **not percentages compounded from earlier stages**. Each displayed absolute number is a median of six role samples; relative changes are medians of the six within-pair ratios, which need not equal the ratio of the two role medians. Raw per-invocation files, exact six samples, metadata, bootstrap intervals and checker output are archived in `incremental-results/` and `overall-results/`.


This experiment measures per-operation elapsed time (ns/op), B/op and allocs/op with a simulated upstream. It does not measure process CPU time or establish Linux throughput, RSS, revocation performance or end-to-end authorization latency. The root experiment separately prepares matched Rust gateway identity and Linux cache-enabled/cache-disabled comparisons.

```sh
python3 docs/experiments/auth-cache-invalidation-20260923/run-benchmarks.py \
  --before-binary /path/to/4d15fa3-proxy.test \
  --after-binary /path/to/6699822-proxy.test \
  --output /path/to/new-incremental-results-directory
python3 docs/experiments/auth-cache-invalidation-20260923/run-benchmarks.py \
  --comparison overall \
  --before-binary /path/to/92d4c0c-proxy.test \
  --after-binary /path/to/6699822-proxy.test \
  --output /path/to/new-overall-results-directory
```

Use the same `hot_path_benchmark_test.go` fixture for both test binaries; fixture SHA256 is `449dc0b1d6ab764da8c3cea7e190ea48d01f3b14f857950c27b348dab54b639d`. Existing six-pair intervals must not be compounded with this incremental comparison.

To build the three pinned test binaries before the measurement window:

```sh
bench_work=$(mktemp -d)
for revision in 92d4c0cb5495d57801d52893a8f0e8496a1c9182 4d15fa32764e26df58b16930d0e2503a90880002 66998225a2d0d78e40390c179681b6a48b5e5635; do
  mkdir "$bench_work/$revision"
  git archive "$revision" | tar -xf - -C "$bench_work/$revision"
  git show 66998225a2d0d78e40390c179681b6a48b5e5635:pkg/proxy/hot_path_benchmark_test.go \
    > "$bench_work/$revision/pkg/proxy/hot_path_benchmark_test.go"
  (cd "$bench_work/$revision" && go test -c -o "$bench_work/$revision.test" ./pkg/proxy)
done
```

After each comparison, run `go run ./tools/benchcheck --base RESULTS/before.txt --current RESULTS/after.txt --max-latency-regression 0.05`. Both recorded commands exited 0. Stop all builds and competing load before running the benchmark driver; do not rebuild between pairs. Prebuilt binaries used in this run were independently hashed and their unchanged fixture verified before the CPU window.
