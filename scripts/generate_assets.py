#!/usr/bin/env python3
"""Generate lookup CSVs and simple PNG app icons (no third-party deps)."""

from __future__ import annotations

import csv
import os
import struct
import sys
import zlib

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BIN = os.path.join(ROOT, "es_finding_evidence", "bin")
sys.path.insert(0, BIN)

from lib.evidence import EVIDENCE_CLASSES  # noqa: E402
from lib.templates import templates_as_rows  # noqa: E402
from lib.demo import sample_findings  # noqa: E402


def write_csv(path: str, rows: list[dict], fieldnames: list[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def png(path: str, size: int, color: tuple[int, int, int]) -> None:
    """Solid rounded-ish square PNG so Splunk has an app icon."""
    r, g, b = color
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            edge = min(x, y, size - 1 - x, size - 1 - y)
            if edge < size * 0.08:
                raw.extend((11, 24, 38, 0))
            else:
                # inner shield band
                cx, cy = size / 2, size / 2 + size * 0.05
                dx, dy = (x - cx) / (size * 0.32), (y - cy) / (size * 0.38)
                inside = dx * dx + dy * dy * 0.85 < 1
                if inside:
                    raw.extend((r, g, b, 255))
                else:
                    raw.extend((11, 61, 92, 255))
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    payload = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(payload)


def main() -> None:
    lookups = os.path.join(ROOT, "es_finding_evidence", "lookups")
    weights = []
    for name, meta in sorted(EVIDENCE_CLASSES.items()):
        weights.append(
            {
                "class": name,
                "source": meta["source"],
                "direction": meta["direction"],
                "base_weight": meta["weight"],
                "description": name.replace("_", " "),
            }
        )
    write_csv(
        os.path.join(lookups, "evidence_weights.csv"),
        weights,
        ["class", "source", "direction", "base_weight", "description"],
    )
    write_csv(
        os.path.join(lookups, "search_templates.csv"),
        templates_as_rows(),
        [
            "template_id",
            "name",
            "purpose",
            "evidence_class",
            "direction",
            "base_weight",
            "priority",
            "requires",
            "mitre",
            "category",
            "spl",
        ],
    )
    sample_rows = []
    for finding in sample_findings():
        sample_rows.append(
            {
                "finding_id": finding["finding_id"],
                "title": finding.get("rule_title"),
                "urgency": finding.get("urgency"),
                "user": finding.get("user", ""),
                "src": finding.get("src", ""),
                "dest": finding.get("dest", ""),
                "risk_score": finding.get("risk_score", ""),
                "triage_disposition": finding.get("triage_disposition", ""),
            }
        )
    write_csv(
        os.path.join(lookups, "sample_findings.csv"),
        sample_rows,
        ["finding_id", "title", "urgency", "user", "src", "dest", "risk_score", "triage_disposition"],
    )
    static = os.path.join(ROOT, "es_finding_evidence", "appserver", "static")
    png(os.path.join(static, "appIcon.png"), 36, (91, 163, 217))
    png(os.path.join(static, "appIcon_2x.png"), 72, (91, 163, 217))
    png(os.path.join(static, "appIconAlt.png"), 36, (242, 169, 59))
    png(os.path.join(static, "appIconAlt_2x.png"), 72, (242, 169, 59))
    print("wrote lookups and icons")


if __name__ == "__main__":
    main()
