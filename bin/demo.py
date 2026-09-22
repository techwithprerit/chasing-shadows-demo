#!/usr/bin/env python3
"""
The eight minutes on stage (slides 26-33).

  Flow 01  replay -> monitor -> PPL
    1  _simulate one poisoned span; watch context.hash and pace_cv appear
    2  _bulk the withheld tail of the replay into traces-agent-demo
    3  _execute the monitor; the flat-line trigger fires for one agent
    4  pivot from the alert into PPL: the two hunts

  Flow 02  detector -> findings
    5  agent-egress-pace over agent-metrics-1m; the per-entity grades
    6  inject a scripted agent; watch its grade climb across two intervals
    7  Security Analytics findings, correlated to the same agent
    8  drilldown: finding -> trace -> the README that started it

Every step pauses for Enter so you control the pace. --no-pause runs it end to
end for rehearsal; --step N starts partway through when you are practising one
beat. Nothing here mutates anything a re-run cannot repeat.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import random
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from detect import (  # noqa: E402
    STATE_PATH,
    ensure_detector_id,
    entity_grades,
    flat_line_buckets,
    load_state,
    save_state,
    wait_for_historical,
)
from generator.generate import METRONOME_GAP_MS, METRONOME_JITTER_MS, PATIENT_ZERO, iso  # noqa: E402
from ml.triage_fallback import ScriptedTriage, run_real_agent, _rows  # noqa: E402
from os_http import ENV, OS, REPO_ROOT, OpenSearchError, say, say_ok, say_warn  # noqa: E402

DASHBOARDS = ENV.get("DASHBOARDS_URL", "http://localhost:5601")
INJECT_AGENT = "cw-runner-042"


class Demo:
    def __init__(self, os_: OS, state: dict, pause: bool):
        self.os = os_
        self.state = state
        self.pause = pause
        self.hash = state.get("poison_hash", "")

    # -- presentation helpers ------------------------------------------------ #
    def head(self, number: int, title: str, api: str) -> None:
        say("\n" + "=" * 78)
        say(f"  STEP {number}  ·  {title}")
        say(f"  {api}")
        say("=" * 78)

    def hold(self) -> None:
        if self.pause:
            try:
                input("\n  [enter] ")
            except (EOFError, KeyboardInterrupt):
                raise SystemExit("\nstopped")

    @staticmethod
    def table(rows: list[dict], columns: list[tuple[str, str, int]]) -> None:
        header = "  ".join(label.ljust(width) for _, label, width in columns)
        say("    " + header)
        say("    " + "-" * len(header))
        for row in rows:
            cells = []
            for key, _, width in columns:
                value = row.get(key, "")
                if isinstance(value, float):
                    value = f"{value:,.3f}" if abs(value) < 100 else f"{value:,.0f}"
                elif isinstance(value, int):
                    value = f"{value:,}"
                cells.append(str(value)[:width].ljust(width))
            say("    " + "  ".join(cells))

    # -- flow 01 ------------------------------------------------------------- #
    def step1(self) -> None:
        self.head(1, "One poisoned span through the pipeline",
                  "POST _ingest/pipeline/sec-normalise/_simulate")
        span = json.loads((REPO_ROOT / "data" / "poisoned-span.json").read_text())
        say("\n    in  — what the collector sent (abridged):")
        say(f"      gen_ai.tool.name          {span['gen_ai']['tool']['name']}")
        say(f"      url.full                  {span['url']['full']}")
        say(f"      agent.recent_gaps_ms      {span['agent']['recent_gaps_ms'][:4]} ... "
            f"({len(span['agent']['recent_gaps_ms'])} values)")
        say(f"      gen_ai.tool.input.document  {len(span['gen_ai']['tool']['input']['document']):,} bytes of README")

        result = self.os.post("_ingest/pipeline/sec-normalise/_simulate", {"docs": [{"_source": span}]})
        doc = result["docs"][0].get("doc")
        if not doc:
            say_warn("the pipeline dropped this span - a drop condition now matches it")
            return
        out = doc["_source"]

        say("\n    out — what the cluster stored:")
        say(f"      context.hash              {out.get('context', {}).get('hash')}")
        say(f"      agent.pace_cv             {out.get('agent', {}).get('pace_cv')}")
        say(f"      agent.tool_rate           {out.get('agent', {}).get('tool_rate')}")
        say(f"      agent.tokens_per_call     {out.get('agent', {}).get('tokens_per_call')}")
        say(f"      asset.team                {out.get('asset', {}).get('team')}")
        say(f"      url.novelty               {out.get('url', {}).get('novelty')}")
        say(f"      gen_ai.tool.input.document  {'gone' if 'input' not in out['gen_ai'].get('tool', {}) else 'STILL HERE'}")
        say(f"      agent.recent_gaps_ms      {'gone' if 'recent_gaps_ms' not in out.get('agent', {}) else 'STILL HERE'}")
        say("\n    Two derived numbers and a fingerprint, computed once, at write time.")
        say("    The document body and the gap window leave before anything is written.")

    def step2(self) -> None:
        self.head(2, "Bulk the withheld tail of the replay", "POST _bulk -> traces-agent-demo")
        tail_path = REPO_ROOT / "data" / "replay-tail.ndjson"
        if not tail_path.exists():
            say_warn("data/replay-tail.ndjson is missing - run bin/load.py to regenerate it")
            return
        lines = tail_path.read_text().splitlines()
        before = self.os.count("traces-agent-demo")
        started = time.time()
        failures = self.os.bulk(lines, refresh=True)
        elapsed = time.time() - started
        after = self.os.count("traces-agent-demo")
        say(f"\n    {len(lines) // 2:,} documents in {elapsed:.2f}s   ({failures} failures)")
        say(f"    traces-agent-demo: {before:,} -> {after:,}")
        say("\n    The last fifteen minutes of the night, arriving the way they arrived then.")

    def step3(self) -> None:
        self.head(3, "The monitor that caught it",
                  f"POST _plugins/_alerting/monitors/{self.state['monitor_id']}/_execute")
        result = self.os.post(
            f"_plugins/_alerting/monitors/{self.state['monitor_id']}/_execute",
            params={"dryrun": "false"},
        )
        buckets = flat_line_buckets(result)
        say("\n    trigger 'flat-line' fired for:")
        for bucket in buckets:
            key = bucket["key"]
            say(f"      agent={key.get('agent')}  host={key.get('host')}  "
                f"calls={bucket['doc_count']}  bytes_out={bucket['out']['value']:,.0f}  "
                f"pace_cv={bucket['cv']['value']:.3f}")
        if not buckets:
            say_warn("no buckets fired. Most likely the replay has drifted out of the monitor's "
                     "2h window - run 'make reload' and re-run bin/detect.py.")
        say("\n    params._count > 60 and params.cv < 0.10 and params.out > 200000,")
        say("    over a two-hour window. Two hundred and twelve agents; one pair matched.")
        say("    Note what is NOT in that condition: a volume threshold big enough to notice.")
        say("    4 KB every thirty seconds is 492 KB an hour. That sat inside the daily")
        say("    quota all night. The flat line is the signal, not the volume.")

    def step4(self) -> None:
        self.head(4, "Pivot from the alert into PPL", "POST _plugins/_ppl")

        say("\n  02:41 · who is a metronome?\n")
        query1 = (
            "source = traces-agent-* "
            "| where gen_ai.tool.name = 'http_fetch' "
            "| stats sum(http.request.body.size) as out, "
            "stddev_samp(http.request.body.size) as jitter, count() as n "
            "by span(`@timestamp`, 5m), gen_ai.agent.id, url.domain "
            "| eval flat = jitter / (out / n) "
            "| where n > 8 and flat < 0.05 "
            "| sort - out | head 10"
        )
        say("    " + query1.replace(" | ", "\n    | "))
        try:
            rows = _rows(self.os.ppl(query1))
            say("")
            self.table(
                rows[:10],
                [("gen_ai.agent.id", "agent", 16), ("url.domain", "host", 24),
                 ("n", "calls", 7), ("out", "bytes out", 12), ("flat", "flat", 8)],
            )
            say(f"\n    {len(rows)} five-minute windows where the byte size never moved.")
        except OpenSearchError as exc:
            say_warn(f"PPL rejected the query ({exc.status}): {exc.body[:240]}")

        self.hold()
        say("\n  02:53 · who else read the poison?\n")
        query2 = (
            f"source = traces-agent-* | where context.hash = '{self.hash}' "
            "| stats count() as reads, min(`@timestamp`) as first_seen "
            "by gen_ai.agent.id, session.id | sort - reads"
        )
        say("    " + query2.replace(" | ", "\n    | "))
        try:
            rows = _rows(self.os.ppl(query2))
            say("")
            self.table(
                rows[:12],
                [("gen_ai.agent.id", "agent", 16), ("session.id", "session", 14),
                 ("reads", "spans", 8), ("first_seen", "first seen", 26)],
            )
            say(f"\n    {len({r['gen_ai.agent.id'] for r in rows})} agents read the same document.")
        except OpenSearchError as exc:
            say_warn(f"PPL rejected the query ({exc.status}): {exc.body[:240]}")

        self.hold()
        say("\n  02:56 · which of them moved on to the credentials?\n")
        self._api_delta()

    def _api_delta(self) -> None:
        """Slide 23 does this with a PPL join. Calcite makes join available from
        3.0, but it is off by default before 3.3 - so try the join, and fall back
        to the aggregation that answers the same question."""
        join_query = (
            f"source = traces-agent-* | where context.hash = '{self.hash}' "
            "| stats count() as reads by gen_ai.agent.id "
            "| join on gen_ai.agent.id = agent.id logs-sec-cloudtrail "
            "| stats dc(event.action) as api_calls by gen_ai.agent.id | sort - api_calls"
        )
        say("    " + join_query.replace(" | ", "\n    | "))
        try:
            rows = _rows(self.os.ppl(join_query))
            say("")
            self.table(rows[:12], [("gen_ai.agent.id", "agent", 16), ("api_calls", "distinct API actions", 22)])
            return
        except OpenSearchError as exc:
            say_warn(f"join unavailable ({exc.status}) - falling back to the two-step form")

        agents = [
            b["key"]
            for b in self.os.search(
                "traces-agent-*",
                {"size": 0, "query": {"term": {"context.hash": self.hash}},
                 "aggs": {"a": {"terms": {"field": "gen_ai.agent.id", "size": 50}}}},
            )["aggregations"]["a"]["buckets"]
        ]
        result = self.os.search(
            "logs-sec-cloudtrail",
            {"size": 0, "query": {"terms": {"agent.id": agents}},
             "aggs": {"a": {"terms": {"field": "agent.id", "size": 50},
                            "aggs": {"api": {"cardinality": {"field": "event.action"}}}}}},
        )
        rows = sorted(
            ({"agent": b["key"], "api_calls": b["api"]["value"]} for b in result["aggregations"]["a"]["buckets"]),
            key=lambda r: -r["api_calls"],
        )
        say("")
        self.table(rows, [("agent", "agent", 16), ("api_calls", "distinct API actions", 22)])
        say("\n    Nine agents had read the README. Eight were still on a different task.")
        say("    One had moved on to the credentials.")

    # -- flow 02 ------------------------------------------------------------- #
    def step5(self) -> None:
        self.head(5, "The detector, per entity",
                  "POST _plugins/_anomaly_detection/detectors/results/_search")
        detector_id = ensure_detector_id(self.os, self.state)
        if not detector_id:
            say_warn("no anomaly detector exists yet - run: python3 bin/detect.py")
            return
        rows = sorted(entity_grades(self.os, detector_id, size=12), key=lambda r: -(r["grade"] or 0))
        say("")
        if rows:
            self.table(rows, [("entity", "agent", 16), ("grade", "peak grade", 12),
                              ("confidence", "confidence", 12), ("findings", "findings", 10)])
            top = rows[0]
            say(f"\n    One RCF model per agent. {top['entity']} grades {top['grade']:.2f} "
                f"at {top['confidence']:.2f} confidence.")
            say("    shingle_size 8 at a 10-minute interval means the model sees an 80-minute")
            say("    shape - so a metronome is anomalous even when its volume is not.")
        else:
            say_warn("no graded results. Run: python3 bin/detect.py --wait")

    def step6(self) -> None:
        self.head(6, f"Inject a scripted agent ({INJECT_AGENT})", "POST _bulk -> agent-metrics-1m")
        detector_id = ensure_detector_id(self.os, self.state)
        if not detector_id:
            say_warn("no anomaly detector exists yet - run: python3 bin/detect.py")
            return
        rng = random.Random(4242)
        now = int(time.time() * 1000)
        now -= now % 60_000
        minutes = 40
        docs = []
        for i in range(minutes):
            minute = now - (minutes - i) * 60_000
            calls = 2
            gaps = [rng.gauss(METRONOME_GAP_MS, METRONOME_JITTER_MS) for _ in range(10)]
            mean = sum(gaps) / len(gaps)
            pace = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5 / mean
            docs.append({
                "@timestamp": iso(minute),
                "gen_ai": {"agent": {"id": INJECT_AGENT}, "tool": {"name": "http_fetch"},
                           "usage": {"output_tokens": {"sum": 24.0}}},
                "http": {"request": {"body": {"size": {"sum": 4096.0 * calls, "max": 4096.0}}}},
                "agent": {"pace_cv": {"avg": round(pace, 5), "min": round(pace * 0.95, 5)},
                          "tokens_per_call": {"avg": 126.0}},
                "tool_calls": {"value_count": float(calls)},
                "url": {"domain": {"cardinality": 1.0}},
                "asset": {"team": "search-relevance"},
            })
        lines = []
        for doc in docs:
            lines.append(json.dumps({"index": {"_index": "agent-metrics-1m"}}))
            lines.append(json.dumps(doc, separators=(",", ":")))
        self.os.bulk(lines, refresh=True)
        say(f"\n    {len(docs)} one-minute rows written for {INJECT_AGENT}: "
            f"4 KB every 30 seconds, one host, pacing CV {docs[-1]['agent']['pace_cv']['avg']:.3f}")
        say(f"    Its own history is normal, which is the point - the model compares it to itself.")

        bounds = self.os.search(
            "agent-metrics-1m",
            {"size": 0, "aggs": {"lo": {"min": {"field": "@timestamp"}}, "hi": {"max": {"field": "@timestamp"}}}},
        )
        lo, hi = int(bounds["aggregations"]["lo"]["value"]), int(bounds["aggregations"]["hi"]["value"])
        self.os.post(f"_plugins/_anomaly_detection/detectors/{detector_id}/_stop", ok=(200, 400, 404))
        self.os.post(f"_plugins/_anomaly_detection/detectors/{detector_id}/_start",
                     {"start_time": lo, "end_time": hi})
        say("\n    historical analysis re-running over the whole window ...")
        wait_for_historical(self.os, detector_id, timeout=420)

        # entity is a nested field in the results index, so the per-entity filter
        # has to be a nested query; fall back to the flat form if this build
        # maps it differently.
        def grades_over_time(entity_filter: dict) -> list[dict]:
            result = self.os.post(
                "_plugins/_anomaly_detection/detectors/results/_search",
                {"size": 0,
                 "query": {"bool": {"filter": [
                     {"term": {"detector_id": detector_id}},
                     entity_filter,
                     {"range": {"anomaly_grade": {"gt": 0}}}]}},
                 "aggs": {"over_time": {
                     "date_histogram": {"field": "data_end_time", "fixed_interval": "10m"},
                     "aggs": {"grade": {"max": {"field": "anomaly_grade"}}}}}},
                ok=(200, 400, 404),
            )
            if not isinstance(result, dict):
                return []
            return [b for b in result.get("aggregations", {}).get("over_time", {}).get("buckets", [])
                    if b["doc_count"]]

        buckets = grades_over_time(
            {"nested": {"path": "entity", "query": {"term": {"entity.value": INJECT_AGENT}}}}
        ) or grades_over_time({"term": {"entity.value": INJECT_AGENT}})

        say("")
        if buckets:
            self.table(
                [{"t": b["key_as_string"][11:16], "grade": b["grade"]["value"]} for b in buckets[-6:]],
                [("t", "interval", 10), ("grade", "anomaly grade", 14)],
            )
            say(f"\n    {INJECT_AGENT} was invisible an hour ago. Nobody wrote a rule for it.")
        else:
            say_warn(f"no graded results for {INJECT_AGENT} yet - the model may need another interval")

    def step7(self) -> None:
        self.head(7, "Signature findings, correlated to the same agent",
                  "GET _plugins/_security_analytics/findings/_search")
        if self.state.get("sa_ok") and self.state.get("sa_detector_id"):
            try:
                result = self.os.get(
                    "_plugins/_security_analytics/findings/_search",
                    params={"detector_id": self.state["sa_detector_id"], "size": 20},
                )
                findings = result.get("findings", [])
                say(f"\n    {len(findings)} findings")
                for finding in findings[:8]:
                    rules = ", ".join(r.get("id", "")[:8] for r in finding.get("queries", []))
                    say(f"      {finding.get('timestamp')}  docs={len(finding.get('related_doc_ids', []))}  rules={rules}")
                if findings:
                    say("\n    Same agent, two independent layers: a model that graded the shape,")
                    say("    and a rule that named the behaviour.")
                    return
                say_warn("detector has not produced findings yet (schedule is 1 minute)")
            except OpenSearchError as exc:
                say_warn(f"findings query failed ({exc.status}) - using the fallback monitor")
        else:
            say_warn("Security Analytics is not active in this run - using the fallback monitor")

        monitor_id = self.state.get("policy_monitor_id")
        result = self.os.post(f"_plugins/_alerting/monitors/{monitor_id}/_execute", params={"dryrun": "true"})
        hits = (result.get("input_results", {}).get("results", [{}])[0].get("hits", {}))
        total = hits.get("total", {}).get("value", 0)
        say(f"\n    query-level monitor 'tool outside harness policy': {total} matching spans")
        buckets = (result.get("input_results", {}).get("results", [{}])[0]
                   .get("aggregations", {}).get("by_agent", {}).get("buckets", []))
        self.table([{"agent": b["key"], "n": b["doc_count"]} for b in buckets],
                   [("agent", "agent", 18), ("n", "violations", 12)])
        say("\n    Two agents drifted outside the tool allow-list. One POSTed a body to a")
        say("    health endpoint. The rule names the behaviour; the model graded the shape.")

    def step8(self) -> None:
        self.head(8, "Finding -> trace -> the README that started it", "GET sec-context-docs")
        result = self.os.search(
            "sec-context-docs", {"size": 1, "query": {"term": {"context.hash": self.hash}}})
        hits = result["hits"]["hits"]
        if not hits:
            say_warn("no context document found")
            return
        doc = hits[0]["_source"]
        say(f"\n    context.hash   {doc['context']['hash']}")
        say(f"    url            {doc['url']['full']}")
        say(f"    title          {doc['doc']['title']}")
        say(f"    verdict        {doc['doc']['verdict']}")
        say(f"    fetched by     {doc['fetched_by_count']} agents")
        say("\n    the span nobody read:\n")
        for line in doc["doc"]["suspicious_span"].split(" ... "):
            say(f"      {line}")
        say("\n    White-on-white text in a vendor README. The agent used only the tools it")
        say("    was given, against endpoints on its allow-list, signed by its own role.")
        say("    The prompt is the perimeter now.")
        say(f"\n    Dashboards: {DASHBOARDS}/app/discover")
        say(f"    Alerting:   {DASHBOARDS}/app/alerting")
        if self.state.get("detector_id"):
            say(f"    Detector:   {DASHBOARDS}/app/anomaly-detection-dashboards#/detectors/{self.state['detector_id']}")

    def step9_triage(self) -> None:
        self.head(9, "Agents triaging agents (optional closer)",
                  "POST _plugins/_ml/agents/<id>/_execute" if self.state.get("agent_id") else "scripted four-hunt runner")
        agent_id = self.state.get("agent_id")
        if agent_id:
            try:
                text, usage = run_real_agent(self.os, agent_id, PATIENT_ZERO, self.hash)
                say("\n" + "\n".join("    " + line for line in text.splitlines()))
                if usage:
                    say(f"\n    token_usage: {json.dumps(usage)}")
                return
            except OpenSearchError as exc:
                say_warn(f"agent execution failed ({exc.status}) - running the scripted triage instead")
        triage = ScriptedTriage(self.os, self.hash, PATIENT_ZERO)
        say("\n" + "\n".join("    " + line for line in triage.run().splitlines()))
        say("\n    Cost: four queries. The model writes the paragraph; the queries do the work.")


STEPS = ["step1", "step2", "step3", "step4", "step5", "step6", "step7", "step8", "step9_triage"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-pause", action="store_true", help="run end to end without waiting")
    parser.add_argument("--step", type=int, default=1, help="start at this step (1-9)")
    parser.add_argument("--only", type=int, help="run a single step")
    args = parser.parse_args()

    state = load_state()
    if not state.get("monitor_id"):
        raise SystemExit(f"{STATE_PATH.name} is empty - run bin/bootstrap.py, bin/load.py, bin/detect.py first")

    os_ = OS()
    demo = Demo(os_, state, pause=not args.no_pause)

    say("\n  Chasing shadows with OpenSearch — live demo")
    say(f"  cluster {os_.url}   patient zero {PATIENT_ZERO}   context.hash {demo.hash[:20]}...")

    if args.only is not None and not 1 <= args.only <= len(STEPS):
        raise SystemExit(f"--only must be between 1 and {len(STEPS)}")
    if not 1 <= args.step <= len(STEPS):
        raise SystemExit(f"--step must be between 1 and {len(STEPS)}")
    chosen = [STEPS[args.only - 1]] if args.only else STEPS[args.step - 1 :]
    for name in chosen:
        getattr(demo, name)()
        if name != chosen[-1]:
            demo.hold()
    say("\n" + "=" * 78)
    say("  Store the derivative. Shape the bytes, keep the signal. Agents recommend,")
    say("  humans revoke.")
    say("=" * 78 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
