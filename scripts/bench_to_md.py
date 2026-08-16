#!/usr/bin/env python3
"""Convert the criterion benchmark output into `github_action_benchmark.md`.

Reads a raw `cargo bench --bench lab` stream (stdout+stderr) and produces a
markdown report with one table per workload class. Two data sources feed the
report:

- `BENCH_BYTES\\t<workload>\\t<codec>\\t<bytes>` lines emitted by the lab for
  each registered codec (the encoded byte counts).
- Criterion's `time: [min median max]` lines, whose preceding benchmark name
  (`<workload>/<codec>/<encode|decode>`) identifies the row.

The script never guesses: a row is only emitted when both the timing and the
byte count are present. Missing rows are reported to stderr.
"""

import argparse
import os
import re
import sys

# workload/codec/op, where op is "encode" or "decode".
TIME_RE = re.compile(r"^\s*time:\s+\[\s*([0-9.]+)\s*(\S+?)\s*[0-9.]+\s*\S+?\s*[0-9.]+\s*\S+?\s*\]")
# Matches a benchmark-name line. Criterion prints the name alone on its
# own line in one mode and "name time: [...]" on a single line in
# another (observed with the rkyv benches); both are handled. The op is
# "encode", "decode", or a suffixed variant such as "encode-v1" /
# "decode-v1-as-v2" (schema-evolution).
LINE_RE = re.compile(
    r"^(?P<wl>[a-z0-9-]+)/(?P<codec>[a-z0-9-]+)/(?P<op>(?:encode|decode)[a-z0-9-]*)"
    r"(?:\s+time:\s+\[(?P<t>[0-9.]+)\s+(?P<u>\S+?)\s*[0-9.]+\s*\S+?\s*[0-9.]+\s*\S+?\s*\])?"
    r"\s*$"
)
# Standalone criterion timing line (name was on the previous line).
TIME_RE = re.compile(
    r"^\s*time:\s+\[\s*([0-9.]+)\s*(\S+?)\s*[0-9.]+\s*\S+?\s*[0-9.]+\s*\S+?\s*\]"
)
BYTES_RE = re.compile(r"^BENCH_BYTES\t([^\t]+)\t([^\t]+)\t(\d+)$")
# Emitted by the lab when a schema-evolution decode probe failed: the codec
# cannot decode V1 bytes as a V2 type with an appended field.
EVO_FAIL_RE = re.compile(r"^BENCH_EVO_FAIL\t([^\t]+)\t([^\t]+)$")

# Criterion's time units.
UNIT_SCALE = {
    "ns": 1.0,
    "µs": 1e3,
    "ms": 1e6,
    "s": 1e9,
}


def parse_time(text: str, unit: str) -> float:
    """Returns the median time in nanoseconds."""
    # Windows PowerShell captures cargo's UTF-8 stdout with the GBK console
    # codepage, which turns the UTF-8 bytes of "µ" (0xC2 0xB5) into the GBK
    # character 碌 (U+788C). Normalise it back so both raw paths parse.
    unit = unit.replace("\u788c", "\u00b5")
    scale = UNIT_SCALE.get(unit)
    if scale is None:
        # Final safety net: criterion only emits ns / µs / ms / s.
        if unit.endswith("ns"):
            scale = UNIT_SCALE["ns"]
        elif unit.endswith("ms"):
            scale = UNIT_SCALE["ms"]
        elif unit == "s":
            scale = UNIT_SCALE["s"]
        else:
            scale = UNIT_SCALE["µs"]
    return float(text) * scale


def fmt_ns(value: float) -> str:
    """Formats a nanosecond value with an appropriate unit."""
    for unit, div in (("ns", 1.0), ("µs", 1e3), ("ms", 1e6), ("s", 1e9)):
        if value < div * 1000:
            return f"{value / div:.1f} {unit}"
    return f"{value / 1e9:.2f} s"


def machine_header() -> str:
    env = os.environ
    fields = [
        ("OS", env.get("BENCH_OS")),
        ("CPU", env.get("BENCH_CPU")),
        ("Rust", env.get("BENCH_RUSTC")),
        ("Run", env.get("BENCH_RUN_ID")),
        ("Date (UTC)", env.get("BENCH_DATE")),
    ]
    lines = ["| field | value |", "| --- | --- |"]
    for name, value in fields:
        lines.append(f"| {name} | {value or 'n/a'} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="raw criterion output file")
    parser.add_argument("output", help="markdown report output path")
    parser.add_argument(
        "--title",
        default="Benchmark lab (criterion)",
        help="report title",
    )
    args = parser.parse_args()

    bytes_by_key: dict[tuple[str, str], int] = {}
    time_by_key: dict[tuple[str, str, str], float] = {}
    order: list[tuple[str, str]] = []
    evo_fail: set[tuple[str, str]] = set()

    def base_op(op: str) -> str:
        """Normalises encode-v1 -> encode, decode-v1-as-v2 -> decode."""
        return op if op in ("encode", "decode") else op.split("-", 1)[0]

    with open(args.input, "rb") as raw:
        head = raw.read(4)
        if head.startswith(b"\xff\xfe"):
            # Windows PowerShell redirects write UTF-16 LE with BOM.
            encoding = "utf-16"
        elif head.startswith(b"\xef\xbb\xbf"):
            encoding = "utf-8-sig"
        else:
            encoding = "utf-8"
    with open(args.input, encoding=encoding, errors="replace") as handle:
        current_name = None
        for raw in handle:
            line = raw.rstrip("\n")
            match = BYTES_RE.match(line)
            if match:
                workload, codec, size = match.groups()
                key = (workload, codec)
                if key not in bytes_by_key:
                    order.append(key)
                bytes_by_key[key] = int(size)
                continue
            failed = EVO_FAIL_RE.match(line)
            if failed:
                evo_fail.add((failed.group(1), failed.group(2)))
                continue
            named = LINE_RE.match(line.strip())
            if named:
                workload = named.group("wl")
                codec = named.group("codec")
                op = named.group("op")
                inline = named.group("t")
                if inline is not None:
                    # name and timing on one line
                    time_by_key[(workload, codec, op)] = parse_time(
                        inline, named.group("u")
                    )
                    current_name = None
                else:
                    current_name = (workload, codec, op)
                continue
            if current_name is not None:
                timed = TIME_RE.match(line)
                if timed:
                    text, unit = timed.group(1), timed.group(2)
                    workload, codec, op = current_name
                    time_by_key[(workload, codec, op)] = parse_time(text, unit)
                    current_name = None

    # schema-evolution benches use suffixed op names (encode-v1,
    # decode-v1-as-v2); normalise them for lookup while keeping the
    # full name for display.
    display_op = {}
    normalised = {}
    for (workload, codec, op), value in time_by_key.items():
        base = base_op(op)
        key = (workload, codec, base)
        normalised.setdefault(key, value)
        display_op[key] = op
    time_by_key = normalised

    workloads = ["homogeneous", "heterogeneous", "borrowed", "adversarial", "schema-evolution"]
    seen_workloads = sorted({w for (w, _) in order}, key=lambda w: workloads.index(w) if w in workloads else 99)

    out = [f"# {args.title}", "", machine_header(), ""]

    missing = []
    for workload in seen_workloads:
        codecs = [codec for (w, codec) in order if w == workload]
        codecs = sorted(set(codecs))
        if not codecs:
            continue
        out.append(f"## {workload}\n")
        out.append("| codec | op | time (median) | encoded bytes |")
        out.append("| --- | --- | ---: | ---: |")
        for codec in codecs:
            for op in ("encode", "decode"):
                key = (workload, codec, op)
                timing = time_by_key.get(key)
                size = bytes_by_key.get((workload, codec))
                if (workload, codec) in evo_fail and op == "decode":
                    # The lab probed this decode and it failed; report the
                    # limitation instead of a fake timing.
                    out.append(
                        f"| {codec} | decode-v1-as-v2 | error (see notes) | {size} |"
                    )
                    continue
                if timing is None or size is None:
                    missing.append(f"{workload}/{codec}/{op}")
                    continue
                shown = display_op.get(key, op)
                out.append(f"| {codec} | {shown} | {fmt_ns(timing)} | {size} |")
        out.append("")

    out.append("## Notes\n")
    out.append(
        "- Measured by [criterion](https://github.com/bheisler/criterion.rs) "
        "(median of many samples, outlier-filtered, `black_box` on every "
        "payload); lower is better on time and bytes.\n"
    )
    out.append(
        "- **borrowed**: bincode 2 and bincode-next are absent because their "
        "`decode_from_slice` requires `T: for<'de> Deserialize<'de>`, which a "
        "borrowed serde type cannot satisfy (a real limitation of those "
        "opponents, reported rather than hidden).\n"
    )
    out.append(
        "- **schema-evolution**: the serde codecs are probed for the "
        "`V1 bytes -> V2 type with an appended #[serde(default)] field` "
        "case. bincode 1, bincode 2 and postcard fail it (their sequential "
        "format carries no field metadata, so the missing value errors); "
        "bincode-next tracks the field count and succeeds. rustbinary "
        "succeeds via stable field IDs. Rows marked `error (see notes)` are "
        "that failure, reported rather than hidden.\n"
    )
    out.append(
        "- Numbers vary by machine and load; the `BENCH_RUN_ID` header above "
        "identifies the exact run that produced this file.\n"
    )

    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")

    for key in sorted(missing):
        print(f"warning: missing data for {key}", file=sys.stderr)
    if missing:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
