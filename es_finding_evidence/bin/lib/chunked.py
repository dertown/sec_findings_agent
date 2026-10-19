"""Minimal Splunk Custom Search Command Protocol v2 (chunked) helper.

Kept self-contained so the app does not need the Splunk Python SDK on disk.
"""

from __future__ import annotations

import csv
import io
import json
import sys
import traceback
from typing import Any, Callable, Iterable, Mapping


class ChunkedCommand:
    generating = False
    streaming = True

    def __init__(self, name: str):
        self.name = name
        self.searchinfo: dict[str, Any] = {}
        self.options: dict[str, str] = {}
        self.session_key = ""
        self.splunkd_uri = "https://127.0.0.1:8089"
        self.username = ""
        self.app = "es_finding_evidence"
        self.sid = ""

    def generate(self) -> Iterable[Mapping[str, Any]]:
        return []

    def stream(self, records: list[dict[str, Any]]) -> Iterable[Mapping[str, Any]]:
        return records

    def run(self, infile=None, outfile=None) -> None:
        infile = infile or sys.stdin.buffer
        outfile = outfile or sys.stdout.buffer
        while True:
            header = infile.readline()
            if not header:
                return
            if not header.startswith(b"chunked "):
                raise RuntimeError(f"Unexpected chunk header: {header!r}")
            parts = header.decode("utf-8").strip().split(",")
            meta_len = int(parts[1])
            body_len = int(parts[2])
            meta = json.loads(infile.read(meta_len).decode("utf-8") or "{}")
            body = infile.read(body_len)
            action = (meta.get("action") or meta.get("type") or "").lower()
            if action == "getinfo":
                self._ingest_searchinfo(meta.get("searchinfo") or {})
                payload = {
                    "type": "stateful" if self.generating else "streaming",
                    "generating": bool(self.generating),
                    "required_fields": ["*"],
                    "maxresultrows": 50000,
                }
                self._write(outfile, {"finished": True}, json.dumps(payload).encode("utf-8"))
                continue
            self._ingest_searchinfo(meta.get("searchinfo") or {})
            try:
                if self.generating:
                    rows = list(self.generate())
                else:
                    rows = list(self.stream(self._read_csv(body)))
                finished = True
            except Exception as exc:  # noqa: BLE001 - surface to Splunk job inspector
                err = f"{self.name} failed: {exc}"
                detail = traceback.format_exc()
                self._write(
                    outfile,
                    {
                        "finished": True,
                        "inspector": {"messages": [["ERROR", err], ["ERROR", detail[-2000:]]]},
                        "error": err,
                    },
                    b"",
                )
                return
            csv_body = self._write_csv(rows)
            self._write(outfile, {"finished": finished}, csv_body)

    def _ingest_searchinfo(self, searchinfo: Mapping[str, Any]) -> None:
        if not searchinfo:
            return
        self.searchinfo = dict(searchinfo)
        self.session_key = str(searchinfo.get("session_key") or "")
        self.splunkd_uri = str(searchinfo.get("splunkd_uri") or self.splunkd_uri)
        self.username = str(searchinfo.get("username") or "")
        self.app = str(searchinfo.get("app") or self.app)
        self.sid = str(searchinfo.get("sid") or "")
        args = list(searchinfo.get("raw_args") or searchinfo.get("args") or [])
        parsed: dict[str, str] = {}
        for arg in args:
            text = str(arg)
            if "=" in text:
                key, value = text.split("=", 1)
                parsed[key.strip().lstrip("-")] = value.strip().strip("\"'")
            else:
                parsed[text.strip().lstrip("-")] = "true"
        self.options.update(parsed)

    @staticmethod
    def _write(outfile, metadata: Mapping[str, Any], body: bytes) -> None:
        meta_bytes = json.dumps(metadata).encode("utf-8")
        header = f"chunked 1.0,{len(meta_bytes)},{len(body)}\n".encode("utf-8")
        outfile.write(header)
        outfile.write(meta_bytes)
        outfile.write(body)
        outfile.flush()

    @staticmethod
    def _read_csv(body: bytes) -> list[dict[str, Any]]:
        if not body:
            return []
        text = body.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        return [dict(row) for row in reader]

    @staticmethod
    def _write_csv(rows: list[Mapping[str, Any]]) -> bytes:
        if not rows:
            return b""
        fieldnames: list[str] = []
        seen = set()
        for row in rows:
            for key in row.keys():
                if key not in seen:
                    seen.add(key)
                    fieldnames.append(str(key))
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})
        return buf.getvalue().encode("utf-8")


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, default=str)
    return str(value)


def option(options: Mapping[str, str], name: str, default: str = "") -> str:
    return str(options.get(name, default) if options.get(name, default) is not None else default)


def option_int(options: Mapping[str, str], name: str, default: int) -> int:
    try:
        return int(float(option(options, name, str(default))))
    except (TypeError, ValueError):
        return default


def option_float(options: Mapping[str, str], name: str, default: float) -> float:
    try:
        return float(option(options, name, str(default)))
    except (TypeError, ValueError):
        return default
