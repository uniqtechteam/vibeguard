#!/usr/bin/env python3
"""Render docs/img/demo.svg from a real run of vibeguard on tests/fixtures/demo-app.

Usage: cargo build --release && python3 bench/demo_svg.py [path/to/vibeguard]
The text is the binary's own output; only colours are added, and findings after the first few are
replaced by one "…" line so the image stays readable.
"""
import html
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target" / "release" / "vibeguard"
SHOW_FINDINGS = 3
WRAP = 96

out = subprocess.run(
    [BIN, "scan", "demo-app"], cwd=ROOT / "tests" / "fixtures", capture_output=True, text=True
).stdout.rstrip("\n").splitlines()

lines: list[tuple[str, str]] = [("prompt", "$ vibeguard scan demo-app"), ("blank", "")]
shown = 0
skipping = False
for line in out:
    if line.startswith("  ") and not line.startswith("    "):
        shown += 1
        skipping = shown > SHOW_FINDINGS
        if shown == SHOW_FINDINGS + 1:
            lines.append(("dim", "  …"))
            lines.append(("blank", ""))
    if skipping and not (line and line[0].isdigit()):
        continue
    if line in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append((line.lower(), line))
    elif line.startswith("  ") and not line.startswith("    "):
        lines.append(("rule", line))
    elif line.strip().startswith(("Why:", "Fix:")):
        label, rest = line.strip().split(":", 1)
        wrapped = textwrap.wrap(rest.strip(), WRAP - 9)
        for j, part in enumerate(wrapped):
            lines.append(("label" if j == 0 else "text", f"    {label}: {part}" if j == 0 else f"         {part}"))
    elif line.strip().startswith(">"):
        code = line if len(line) <= WRAP + 20 else line[: WRAP + 19] + "…"
        lines.append(("code", code))
    elif line.startswith("    "):
        lines.append(("path", line))
    elif line and line[0].isdigit():
        lines.append(("summary", line))
    else:
        lines.append(("blank", line))

COLORS = {
    "prompt": "#e6edf3", "critical": "#ff7b72", "high": "#f0883e", "medium": "#d29922", "low": "#79c0ff",
    "rule": "#e6edf3", "path": "#8b949e", "code": "#a5d6ff", "label": "#c9d1d9", "text": "#c9d1d9",
    "summary": "#e6edf3", "dim": "#8b949e", "blank": "#c9d1d9",
}
BOLD = {"critical", "high", "medium", "low", "summary"}
line_h, pad, top = 20, 20, 44
width = 1010
height = top + len(lines) * line_h + pad
rows = []
for i, (kind, text) in enumerate(lines):
    y = top + i * line_h + 14
    weight = ' font-weight="700"' if kind in BOLD else ""
    if kind == "rule":
        rid, _, title = text.strip().partition(" ")
        rows.append(
            f'<text x="{pad}" y="{y}" xml:space="preserve" fill="#e6edf3">  <tspan font-weight="700">{html.escape(rid)}</tspan> {html.escape(title)}</text>'
        )
    elif kind == "label":
        label, _, rest = text.partition(":")
        rows.append(
            f'<text x="{pad}" y="{y}" xml:space="preserve" fill="#8b949e">{html.escape(label)}:<tspan fill="{COLORS[kind]}">{html.escape(rest)}</tspan></text>'
        )
    else:
        rows.append(f'<text x="{pad}" y="{y}" xml:space="preserve" fill="{COLORS[kind]}"{weight}>{html.escape(text)}</text>')

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="vibeguard scanning a demo app and reporting problems">
<rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>
<circle cx="22" cy="20" r="6" fill="#ff5f57"/><circle cx="42" cy="20" r="6" fill="#febc2e"/><circle cx="62" cy="20" r="6" fill="#28c840"/>
<g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="13">
{chr(10).join(rows)}
</g>
</svg>
"""
(ROOT / "docs" / "img" / "demo.svg").write_text(svg)
print(f"wrote docs/img/demo.svg ({len(lines)} lines)")
