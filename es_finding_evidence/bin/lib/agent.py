"""Backend Finding Evidence Agent.

Runs as a Splunk modular input, REST job, or `| findingagent` command.
Each cycle: load findings -> (optional) execute evidence searches ->
run configured judges -> persist / emit / optionally annotate.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Mapping, Sequence

from .analyze import demo_records
from .demo import is_demo_finding_id
from .constants import DEFAULT_WINDOW_MINUTES, INVESTIGATE_THRESHOLD, REVIEW_THRESHOLD
from .evidence import evidence_from_executed_search
from .findings import normalize_finding
from .judges.ensemble import run_judges
from .judges.loader import load_judges
from .recommendations import recommend_searches
from .scoring import analyze_finding, flatten_result
from .search_runner import DemoSearchRunner, NullSearchRunner, SearchRunner, SplunkSearchRunner
from .util import dumps


DEFAULT_TASKS = ("gather_evidence", "score", "enrich", "persist", "emit")


class FindingEvidenceAgent:
    def __init__(
        self,
        *,
        mode: str = "auto",
        tasks: Sequence[str] = DEFAULT_TASKS,
        run_searches: bool = True,
        max_searches_per_finding: int = 4,
        search_timeout: int = 25,
        window_minutes: int = DEFAULT_WINDOW_MINUTES,
        limit: int = 25,
        home: str | None = None,
        search_runner: SearchRunner | None = None,
        finding_loader: Callable[..., list[dict[str, Any]]] | None = None,
        persister: Callable[[list[dict[str, Any]]], None] | None = None,
        note_writer: Callable[[dict[str, Any]], None] | None = None,
        enricher: Callable[[dict[str, Any]], None] | None = None,
        kv_judges: list | None = None,
        investigate_threshold: float = INVESTIGATE_THRESHOLD,
        review_threshold: float = REVIEW_THRESHOLD,
        write_notes: bool = False,
        create_investigation: bool = False,
        status: str = "new",
        urgency: str = "",
        finding_id: str = "",
        splunkd_uri: str = "",
        session_key: str = "",
    ):
        self.mode = mode
        self.tasks = [task.strip() for task in tasks if task and task.strip()]
        self.run_searches = run_searches
        self.max_searches_per_finding = max_searches_per_finding
        self.search_timeout = search_timeout
        self.window_minutes = window_minutes
        self.limit = limit
        self.home = home
        self.search_runner = search_runner
        self.finding_loader = finding_loader
        self.persister = persister
        self.note_writer = note_writer
        self.enricher = enricher
        self.investigate_threshold = investigate_threshold
        self.review_threshold = review_threshold
        self.write_notes = write_notes
        self.create_investigation = create_investigation
        self.status = status
        self.urgency = urgency
        self.finding_id = finding_id
        self.splunkd_uri = splunkd_uri
        self.session_key = session_key
        self.judges = load_judges(home)
        if kv_judges:
            from .judge_store import merge_kv_judges

            self.judges = merge_kv_judges(self.judges, kv_judges, home)

    def run(self) -> dict[str, Any]:
        started = time.time()
        records = self._load()
        results = []
        errors = []
        for record in records[: self.limit]:
            try:
                results.append(self._handle(record))
            except Exception as exc:  # noqa: BLE001 - keep the cycle alive
                errors.append({"finding_id": record.get("finding_id") or record.get("id"), "error": str(exc)})
        if self.enricher and "enrich" in self.tasks:
            for item in results:
                try:
                    self.enricher(item)
                except Exception as exc:  # noqa: BLE001
                    errors.append({"task": "enrich", "finding_id": item.get("finding_id"), "error": str(exc)})
                    item["enrichment_posted"] = 0
                    item["enrichment_error"] = str(exc)
        if self.persister and "persist" in self.tasks:
            try:
                self.persister(results)
            except Exception as exc:  # noqa: BLE001
                errors.append({"task": "persist", "error": str(exc)})
        if self.write_notes and self.note_writer and "write_notes" in self.tasks:
            for item in results:
                try:
                    self.note_writer(item)
                except Exception as exc:  # noqa: BLE001
                    errors.append({"task": "write_notes", "finding_id": item.get("finding_id"), "error": str(exc)})
        elapsed = round(time.time() - started, 2)
        return {
            "ok": True,
            "mode": self.mode,
            "count": len(results),
            "elapsed": elapsed,
            "tasks": self.tasks,
            "judges": [j.as_dict() for j in self.judges],
            "results": results,
            "errors": errors,
        }

    def _load(self) -> list[dict[str, Any]]:
        if self.finding_loader:
            return self.finding_loader()
        if self.mode in {"demo", "sample"} or is_demo_finding_id(self.finding_id):
            rows = demo_records()
            if self.finding_id:
                rows = [row for row in rows if row.get("finding_id") == self.finding_id]
            return rows
        if self.session_key and self.splunkd_uri:
            from .es_client import ESClient

            client = ESClient(self.splunkd_uri, self.session_key)
            rows = client.load(
                finding_id=self.finding_id,
                include_notes=True,
                status=self.status,
                urgency=self.urgency,
                limit=self.limit,
            )
            if rows:
                return rows
            if self.mode == "auto":
                return demo_records()
            return []
        if self.mode == "auto":
            return demo_records()
        return []

    def _runner_for(self, finding: Mapping[str, Any]) -> SearchRunner:
        if self.search_runner:
            return self.search_runner
        if not self.run_searches or "gather_evidence" not in self.tasks:
            return NullSearchRunner()
        if self.mode in {"demo", "sample"} or not self.session_key:
            return DemoSearchRunner(finding)
        return SplunkSearchRunner(self.splunkd_uri, self.session_key, timeout=self.search_timeout)

    def _handle(self, record: Mapping[str, Any]) -> dict[str, Any]:
        finding = normalize_finding(record, window_minutes=self.window_minutes)
        searches = recommend_searches(
            finding, window_minutes=self.window_minutes, max_searches=max(self.max_searches_per_finding, 8)
        )
        executed = []
        extra_evidence = []
        if "gather_evidence" in self.tasks and self.run_searches:
            runner = self._runner_for(finding)
            for search in searches[: self.max_searches_per_finding]:
                result = runner.run(str(search.get("search") or ""), timeout=self.search_timeout)
                executed.append(
                    {
                        "template_id": search.get("template_id"),
                        "search_name": search.get("search_name"),
                        "count": result.get("count"),
                        "error": result.get("error"),
                        "summary": result.get("summary"),
                    }
                )
                extra_evidence.append(evidence_from_executed_search(str(finding.get("finding_id")), search, result))
        context = {
            "extra_evidence": extra_evidence,
            "evidence": extra_evidence,
            "searches": searches,
            "executed": executed,
            "window_minutes": self.window_minutes,
            "max_searches": self.max_searches_per_finding,
            "investigate_threshold": self.investigate_threshold,
            "review_threshold": self.review_threshold,
        }
        analysis = analyze_finding(
            finding,
            already_normalized=True,
            extra_evidence=extra_evidence,
            window_minutes=self.window_minutes,
            investigate_threshold=self.investigate_threshold,
            review_threshold=self.review_threshold,
            max_searches=len(searches) or 12,
        )
        context["analysis"] = analysis
        judged = analysis
        if "score" in self.tasks:
            judged_overlay = run_judges(finding, context=context, judges=self.judges, home=self.home)
            analysis["followup_score"] = judged_overlay["followup_score"]
            analysis["investigation_required"] = judged_overlay["investigation_required"]
            analysis["investigation_label"] = judged_overlay["investigation_label"]
            analysis["judges"] = judged_overlay["judges"]
            analysis["judge_rationale"] = judged_overlay["judge_rationale"]
            analysis["override_applied"] = judged_overlay.get("override_applied")
            judged = analysis
        rows = flatten_result(judged, expand="none")
        row = rows[0] if rows else {}
        row["executed_search_count"] = len(executed)
        row["executed_searches_json"] = dumps(executed)
        row["judges_json"] = dumps(judged.get("judges") or [])
        row["agent_tasks"] = ",".join(self.tasks)
        row["override_applied"] = judged.get("override_applied") or ""
        row["enrichment_posted"] = row.get("enrichment_posted") or 0
        row["enrichment_error"] = row.get("enrichment_error") or ""
        return row


def agent_from_options(options: Mapping[str, str], **kwargs: Any) -> FindingEvidenceAgent:
    if options.get("tasks"):
        task_list = [part.strip() for part in str(options.get("tasks")).split(",") if part.strip()]
    else:
        task_list = list(DEFAULT_TASKS)
    write_notes = str(options.get("write_notes") or "false").lower() in {"1", "true", "yes"}
    if write_notes and "write_notes" not in task_list:
        task_list.append("write_notes")
    session_key = kwargs.get("session_key") or ""
    splunkd_uri = kwargs.get("splunkd_uri") or ""
    mode = str(options.get("mode") or kwargs.get("mode") or "auto")
    if session_key and not kwargs.get("kv_judges"):
        try:
            from .kvstore import KvCollection

            kwargs["kv_judges"] = KvCollection(splunkd_uri, session_key, "fea_custom_judges").list()
        except Exception:
            kwargs["kv_judges"] = []
    if session_key and "enrich" in task_list and not kwargs.get("enricher"):
        from .enrichment import build_enrichment, build_note, compact_fields
        from .es_client import ESClient
        from .kvstore import KvCollection

        client = ESClient(splunkd_uri, session_key) if mode not in {"demo", "sample"} else None
        try:
            enrich_kv: KvCollection | None = KvCollection(splunkd_uri, session_key, "finding_enrichment")
        except Exception:
            enrich_kv = None

        def _enrich(row: dict[str, Any]) -> None:
            fid = str(row.get("finding_id") or "")
            full = build_enrichment(row)
            note = build_note(row)
            posted = {"fields": False, "note": False, "error": ""}
            if client and fid:
                posted = client.enrich_finding(fid, compact_fields(row), note)
            row["enrichment_note"] = note
            row["enrichment_posted"] = 1 if (posted.get("note") or posted.get("fields") or mode in {"demo", "sample"}) else 0
            row["enrichment_error"] = posted.get("error") or ""
            stored = dict(full)
            stored.update(
                {
                    "finding_id": fid,
                    "title": row.get("title"),
                    "note": note,
                    "enrichment_posted": row["enrichment_posted"],
                    "enrichment_error": row["enrichment_error"],
                    "_time": row.get("_time"),
                }
            )
            if enrich_kv and fid:
                try:
                    enrich_kv.put(fid, stored)
                except Exception as exc:  # noqa: BLE001
                    row["enrichment_error"] = (row.get("enrichment_error") or "") + ((" | " if row.get("enrichment_error") else "") + f"kv:{exc}")

        kwargs["enricher"] = _enrich
    if write_notes and session_key and not kwargs.get("note_writer"):
        from .es_client import ESClient

        client = ESClient(splunkd_uri, session_key)

        def _write(row: dict[str, Any]) -> None:
            fid = row.get("finding_id")
            if not fid:
                return
            from .enrichment import build_note

            client.post_note(str(fid), build_note(row))

        kwargs["note_writer"] = _write
    return FindingEvidenceAgent(
        mode=str(options.get("mode") or kwargs.get("mode") or "auto"),
        tasks=task_list,
        run_searches=str(options.get("run_searches") or "true").lower() in {"1", "true", "yes"},
        max_searches_per_finding=int(float(options.get("max_searches_per_finding") or 4)),
        search_timeout=int(float(options.get("search_timeout") or 25)),
        window_minutes=int(float(options.get("window_minutes") or DEFAULT_WINDOW_MINUTES)),
        limit=int(float(options.get("limit") or 25)),
        status=str(options.get("status") or "new"),
        urgency=str(options.get("urgency") or ""),
        finding_id=str(options.get("finding_id") or ""),
        write_notes=write_notes,
        create_investigation=str(options.get("create_investigation") or "false").lower() in {"1", "true", "yes"},
        **kwargs,
    )
