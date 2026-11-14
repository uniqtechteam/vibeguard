#!/usr/bin/env python3
"""Measure how long vibeguard takes on generated Next.js projects and draw docs/img/speed.svg.

Usage: cargo build --release && python3 bench/speed.py [path/to/vibeguard]
Writes bench/results.json and docs/img/speed.svg. Nothing here is estimated: every bar is a median of
five real runs on the machine named under the chart.
"""
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "release" / "vibeguard"
SIZES = [1000, 5000, 20000, 50000]
RUNS = 5

COMPONENT = """'use client'
import {{ useState }} from 'react'

export function Card{i}({{ title }}: {{ title: string }}) {{
  const [open, setOpen] = useState(false)
  return <section onClick={{() => setOpen(!open)}}>{{title}} {i}</section>
}}
"""


def make_project(root: Path, files: int) -> None:
    (root / "package.json").write_text(
        '{"dependencies":{"next":"15","@supabase/supabase-js":"2","stripe":"17"}}'
    )
    for i in range(files - 1):
        d = root / "components" / f"group{i % 100}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"Card{i}.tsx").write_text(COMPONENT.format(i=i))


def cpu_name() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def measure() -> list[dict]:
    results = []
    for size in SIZES:
        with tempfile.TemporaryDirectory() as tmp:
            make_project(Path(tmp), size)
            subprocess.run([BIN, "scan", tmp, "--quiet"], capture_output=True)  # warm the file cache
            times = []
            for _ in range(RUNS):
                start = time.perf_counter()
                subprocess.run([BIN, "scan", tmp, "--quiet", "--fail-on", "never"], capture_output=True, check=True)
                times.append(time.perf_counter() - start)
            results.append({"files": size, "median_s": round(statistics.median(times), 4)})
            print(f"{size:>6} files: {statistics.median(times) * 1000:7.1f} ms")
    return results


def svg(results: list[dict], machine: str, day: str) -> str:
    width, bar_h, gap, left, top = 640, 34, 16, 120, 56
    height = top + len(results) * (bar_h + gap) + 56
    longest = max(r["median_s"] for r in results)
    scale = (width - left - 120) / longest
    rows = []
    for i, r in enumerate(results):
        y = top + i * (bar_h + gap)
        w = max(2, r["median_s"] * scale)
        ms = r["median_s"] * 1000
        label = f"{ms:.0f} ms" if ms >= 10 else f"{ms:.1f} ms"
        rows.append(
            f'<text x="{left - 12}" y="{y + bar_h / 2 + 5}" text-anchor="end" class="axis">{r["files"]:,} files</text>'
            f'<rect x="{left}" y="{y}" width="{w:.1f}" height="{bar_h}" rx="4" class="bar"/>'
            f'<text x="{left + w + 8:.1f}" y="{y + bar_h / 2 + 5}" class="value">{label}</text>'
        )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="vibeguard scan time by project size">
<style>
  .title {{ font: 600 16px system-ui, sans-serif; fill: #1f2328; }}
  .axis, .value {{ font: 13px system-ui, sans-serif; fill: #1f2328; }}
  .note {{ font: 11px system-ui, sans-serif; fill: #59636e; }}
  .bar {{ fill: #2f7d4f; }}
  @media (prefers-color-scheme: dark) {{
    .title, .axis, .value {{ fill: #e6edf3; }} .note {{ fill: #9198a1; }} .bar {{ fill: #3fb950; }}
  }}
</style>
<text x="{left}" y="30" class="title">Time to scan a whole project (median of {RUNS} runs)</text>
{''.join(rows)}
<text x="{left}" y="{height - 18}" class="note">vibeguard {version()} · {machine} · {day} · bench/speed.py</text>
</svg>
"""


def version() -> str:
    out = subprocess.run([BIN, "--version"], capture_output=True, text=True).stdout.strip()
    return out.split()[-1] if out else "?"


def main() -> None:
    if not BIN.exists():
        sys.exit(f"build first: cargo build --release ({BIN} not found)")
    results = measure()
    machine = f"{cpu_name()}, {os.cpu_count()} threads, {platform.system()}"
    day = date.today().isoformat()
    (ROOT / "bench" / "results.json").write_text(
        json.dumps({"version": version(), "machine": machine, "date": day, "runs": RUNS, "results": results}, indent=2) + "\n"
    )
    (ROOT / "docs" / "img" / "speed.svg").write_text(svg(results, machine, day))
    print("wrote bench/results.json and docs/img/speed.svg")


if __name__ == "__main__":
    main()
