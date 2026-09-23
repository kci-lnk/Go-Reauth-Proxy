#!/usr/bin/env python3
"""Build pinned revisions and reproduce the six-sample, alternating A/B runs."""
import argparse
import json
import pathlib
import platform
import statistics
import subprocess
import tempfile
import time

REVISIONS = {
    "base": "92d4c0cb5495d57801d52893a8f0e8496a1c9182",
    "capture": "0cc5ef5d65bfb0a5b2e52ba493241d85fbe0e3ee",
    "lazy": "eb08cbb8acf166976192e112794c930656dcd385",
    "immutable": "894d1122cefb0343df57566e4a5e023479cb0b10",
    "binary": "2a54d3054904f21c4faadaad67fc6e85320bf2ae",
    "candidate": "91f65ccd9eae6441cd02abb064cf83f10c1a5c84",
}
PRIMARY = r"^(BenchmarkHandlerHotPath(AuthOff|CacheHit)|BenchmarkAuthCombinedCacheLookupsCookie|BenchmarkAuthCacheHighCardinalityURLWritesCapacity8192(Parallel)?|BenchmarkReservedCookieStripping|BenchmarkTraceHeaderClassification)$"
ISOLATED = r"^BenchmarkHandlerIsolated$/(Path|Host)/(AuthOff|CombinedCacheHit)/1KiB$"


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def summarize(path):
    values = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields or not fields[0].startswith("Benchmark") or "ns/op" not in fields:
            continue
        values.setdefault(fields[0], []).append([
            float(fields[fields.index(unit) - 1])
            for unit in ("ns/op", "B/op", "allocs/op")
        ])
    return {
        name: {"median": [statistics.median(v[i] for v in samples) for i in range(3)],
               "samples": len(samples)}
        for name, samples in values.items()
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[3])
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    metadata = {"revisions": REVISIONS, "cpu": 2, "samples": 6,
                "primary_benchtime": "500ms", "e2e_and_stage_benchtime": "300ms",
                "platform": platform.platform(), "started": time.time(),
                "go": subprocess.check_output(["go", "version"], text=True).strip()}
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with tempfile.TemporaryDirectory(prefix="auth-hot-path-") as work:
        work = pathlib.Path(work)
        binaries = {}
        benchmark = subprocess.check_output([
            "git", "-C", str(args.repo), "show",
            REVISIONS["candidate"] + ":pkg/proxy/hot_path_benchmark_test.go",
        ])
        for name, revision in REVISIONS.items():
            source = work / name
            source.mkdir()
            archive = work / (name + ".tar")
            with archive.open("wb") as target:
                run(["git", "-C", str(args.repo), "archive", revision], stdout=target)
            run(["tar", "-xf", str(archive), "-C", str(source)])
            # Apply the same measurement fixture to every revision. Production
            # source is always exactly the pinned commit; no source patches.
            (source / "pkg/proxy/hot_path_benchmark_test.go").write_bytes(benchmark)
            binaries[name] = work / (name + ".test")
            run(["go", "test", "-c", "-o", str(binaries[name]), "./pkg/proxy"], cwd=source)

        def measure(name, suffix, pattern, duration, mode="a"):
            with (output / (name + suffix + ".txt")).open(mode) as target:
                run([str(binaries[name]), "-test.run=^$", "-test.bench=" + pattern,
                     "-test.benchmem", "-test.cpu=2", "-test.benchtime=" + duration],
                    stdout=target, stderr=subprocess.STDOUT)

        for name in ("base", "candidate"):
            measure(name, "-warm", PRIMARY, "200ms", "w")
        for suffix, pattern, duration in (
            ("", PRIMARY, "500ms"), ("-e2e", "^BenchmarkHandlerEndToEnd", "300ms"),
        ):
            for sample in range(6):
                names = ("base", "candidate") if sample % 2 == 0 else ("candidate", "base")
                for name in names:
                    print(suffix or "primary", sample + 1, name, flush=True)
                    measure(name, suffix, pattern, duration)
        for sample in range(6):
            names = list(REVISIONS)
            if sample % 2:
                names.reverse()
            for name in names:
                print("stages", sample + 1, name, flush=True)
                measure(name, "-isolated", ISOLATED, "300ms")
    summary = {path.stem: summarize(path) for path in output.glob("*.txt")}
    (output / "summary-all.json").write_text(json.dumps(summary, indent=2) + "\n")
    for suffix in ("", "-e2e"):
        with (output / ("gate" + suffix + ".txt")).open("w") as target:
            run(["go", "run", "./tools/benchcheck", "--base", str(output / ("base" + suffix + ".txt")),
                 "--current", str(output / ("candidate" + suffix + ".txt"))], cwd=args.repo, stdout=target)


if __name__ == "__main__":
    main()
