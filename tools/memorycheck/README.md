# Isolated proxy memory comparison

`run.py` runs Linux test executables built from two revisions. It never reads
production configuration, connects to its control plane, or uses its ports.
Each synthetic upstream, proxy, and load generator is a separate process.
All listeners use automatically assigned loopback ports. Proxy traffic uses
TLS (HTTP/1.1 or HTTP/2); upstream traffic is HTTP/1.1. This measures the actual
proxy transport and response coalescer, not the entire authenticated gateway.
Existing package acceptance tests cover full-handler behavior separately.

Build both revisions using the same Go toolchain and copy ONLY
`pkg/proxy/memory_acceptance_test.go` into the base revision before compilation:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o candidate.test ./pkg/proxy
# Run the same command in the base checkout, with -o baseline.test.
python3 tools/memorycheck/run.py --base ./baseline.test --candidate ./candidate.test --output results
```

Default phases:

- Six alternating performance rounds at concurrency 1/16/64, for small, known
  length, and unknown length responses over HTTP/1.1 and HTTP/2. Additional
  HTTP/2 slow-reader cases pace each 64 KiB chunk by 1 ms. Each sample uses the same baseline client executable in a
  separate process. Each client first completes concurrent warmup requests,
  then signals READY. The controller snapshots proxy allocations and sends
  the measurement start signal. Connection/TLS startup is excluded from the
  steady-state throughput, P95 and allocation counters. The proxy is prewarmed.
- A controlled 64 MiB live-buffer burst, followed by 40 seconds idle and one
  test-only GC. The burst first collects with all buffers still held, so the
  baseline sync.Pool retains victims through the subsequent collection. This
  isolates retained references rather than claiming normal traffic retains
  precisely this amount. Heap profiles are saved.
- A separate burst and five-minute natural recovery trace, without forced GC,
  sampled every ten seconds. Then a second burst and one test-only GC.
- Existing wire acceptance benchmarks, one warmup followed by six alternating
  measured rounds. Use `tools/benchcheck` with `--max-latency-regression 0.03`.

The environment is fixed at `GOMAXPROCS=4`, `GOGC=100`, `GOMEMLIMIT=off` for both
revisions; production GC settings are not consulted or modified. No
`FreeOSMemory` is used. Snapshots count allocations since the previous sample,
so small control-endpoint allocations are included. RSS and CPU are read from
only the proxy process, excluding upstream and client memory. VmHWM is the
kernel-reported high-water value, not a per-case peak. These are localhost measurements,
not an external network bandwidth guarantee.

`performance.json` contains medians, fractional changes and pass/fail at 3%
throughput/latency and the existing 5% allocation gate (plus one rounded
allocation). `samples.jsonl` preserves all raw results. A failed gate is not
silently averaged away across scenarios; a failed performance gate produces
a nonzero exit status after the requested phases finish. Workers are terminated on completion,
exception, or Ctrl-C. Output files remain for review.

Use `--bench-pattern` and `--bench-time` to repeat a specific noisy benchmark.
An A/A control can pass the same executable to both `--base` and `--candidate`.

Use `--case slow/64/2 --seconds 5` for an isolated longer slow-reader sample.
Repeat `--case` to select several scenarios. Original failed samples should
be retained alongside any follow-up measurements.
