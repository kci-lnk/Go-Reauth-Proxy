#!/usr/bin/env python3
"""Compare prebuilt proxy test binaries, alternating six A/B and B/A pairs."""
import argparse
import hashlib
import json
import pathlib
import platform
import random
import statistics
import subprocess
import time

PATTERN = r"^BenchmarkHandlerHotPath(AuthOff|CacheHit)$"
REVISIONS = {
    "fix": {
        "before": "0f16a93b15555afbbd2c6ac7f4c813debb2290b1",
        "after": "748c97e03f6fb9087ac0b3c90064611dc2c6cf66",
    },
    "overall": {
        "before": "92d4c0cb5495d57801d52893a8f0e8496a1c9182",
        "after": "748c97e03f6fb9087ac0b3c90064611dc2c6cf66",
    },
}


def parse(output):
    result = {}
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].startswith("Benchmark") and "ns/op" in fields:
            result[fields[0]] = {
                unit: float(fields[fields.index(unit) - 1])
                for unit in ("ns/op", "B/op", "allocs/op")
            }
    if len(result) != 2:
        raise RuntimeError("expected both lean handler benchmarks")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-binary", type=pathlib.Path, required=True)
    parser.add_argument("--after-binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--comparison", choices=REVISIONS, default="fix")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    revisions = REVISIONS[args.comparison]
    binaries = {role: getattr(args, role + "_binary").resolve() for role in revisions}
    metadata = {
        "revisions": revisions, "pattern": PATTERN, "cpu": 2, "pairs": 6,
        "warmup_benchtime": "200ms", "measurement_benchtime": "1s",
        "platform": platform.platform(), "started_unix": time.time(),
        "go": subprocess.check_output(["go", "version"], text=True).strip(),
        "binary_sha256": {role: hashlib.sha256(path.read_bytes()).hexdigest()
                          for role, path in binaries.items()},
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")

    def measure(role, label, duration):
        command = [str(binaries[role]), "-test.run=^$", "-test.bench=" + PATTERN,
                   "-test.benchmem", "-test.cpu=2", "-test.benchtime=" + duration]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        (output / (label + "-" + role + ".txt")).write_text(result.stdout)
        result.check_returncode()
        return parse(result.stdout)

    for role in binaries:
        measure(role, "warm", "200ms")
    pairs = []
    for number in range(1, 7):
        order = ["before", "after"] if number % 2 else ["after", "before"]
        pair = {}
        for role in order:
            print("pair", number, role, flush=True)
            pair[role] = measure(role, "pair-%02d" % number, "1s")
        pairs.append(pair)
    for role in binaries:
        (output / (role + ".txt")).write_text("".join(
            path.read_text() for path in sorted(output.glob("pair-??-" + role + ".txt"))))
    summary = {}
    rng = random.Random(20260923)
    for name in pairs[0]["before"]:
        values = {}
        for unit in ("ns/op", "B/op", "allocs/op"):
            before = [pair["before"][name][unit] for pair in pairs]
            after = [pair["after"][name][unit] for pair in pairs]
            changes = [(a / b - 1) * 100 for b, a in zip(before, after)]
            samples = sorted(statistics.median(rng.choices(changes, k=len(changes)))
                             for _ in range(10000))
            values[unit] = {
                "before": before, "after": after,
                "before_median": statistics.median(before),
                "after_median": statistics.median(after),
                "paired_change_pct": changes,
                "paired_median_change_pct": statistics.median(changes),
                "paired_bootstrap95_median_change_pct": [samples[250], samples[9749]],
            }
        summary[name] = values
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for name, metrics in summary.items():
        print(name, ", ".join("%s: %.3f%%" % (unit, data["paired_median_change_pct"])
                              for unit, data in metrics.items()))


if __name__ == "__main__":
    main()
