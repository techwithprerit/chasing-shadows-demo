#!/usr/bin/env python3
"""
Answer "why is that panel empty?" without you having to know where to look.

Prints, in order: what is in the cluster, when it is timestamped relative to
now, whether the dashboard's time window still covers it, whether the exact
queries behind the four dashboard panels return anything, and what state the
demo thinks it is in. Ends with a plain-language verdict.

Read-only. Safe to run at any time, including mid-rehearsal.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from detect import find_detector_id, load_state, result_count  # noqa: E402
from os_http import OS, OpenSearchError, say, say_ok, say_step, say_warn  # noqa: E402

TARGETS = ["traces-agent-demo", "logs-sec-cloudtrail", "logs-sec-dns", "logs-sec-vpcflow",
           "agent-metrics-1m", "asset-owner", "sec-context-docs"]
DASHBOARD_WINDOW_HOURS = 7  # matches timeFrom: now-7h in the saved dashboard

problems: list[str] = []


def hours_ago(ms: float | None) -> str:
    if not ms:
        return "-"
    delta = (time.time() * 1000 - ms) / 3_600_000
    return f"{delta:5.1f}h ago"


def inventory(os_: OS) -> dict:
    say_step("What is in the cluster")
    say(f"    {'index / data stream':<22s} {'docs':>10s}  {'oldest':>12s}  {'newest':>12s}")
    say("    " + "-" * 62)
    bounds = {}
    for name in TARGETS:
        count = os_.count(name)
        lo = hi = None
        if count:
            agg = os_.search(name, {"size": 0, "aggs": {
                "lo": {"min": {"field": "@timestamp"}}, "hi": {"max": {"field": "@timestamp"}}}},
                ok=(200, 400, 404))
            if isinstance(agg, dict):
                lo = agg.get("aggregations", {}).get("lo", {}).get("value")
                hi = agg.get("aggregations", {}).get("hi", {}).get("value")
        bounds[name] = (count, lo, hi)
        say(f"    {name:<22s} {count:>10,}  {hours_ago(lo):>12s}  {hours_ago(hi):>12s}")
        if count == 0:
            problems.append(f"{name} is empty - run: python3 bin/load.py")
    return bounds


def time_window(bounds: dict) -> None:
    say_step(f"Does the dashboard's window (now-{DASHBOARD_WINDOW_HOURS}h) still cover the data?")
    cutoff = time.time() * 1000 - DASHBOARD_WINDOW_HOURS * 3_600_000
    for name in ["traces-agent-demo", "logs-sec-cloudtrail"]:
        count, lo, hi = bounds.get(name, (0, None, None))
        if not count or hi is None:
            continue
        if hi < cutoff:
            say_warn(f"{name}: newest document is {hours_ago(hi)} - entirely OUTSIDE the window")
            problems.append(f"{name} has drifted out of the dashboard window - run: make reload")
        elif lo is not None and lo < cutoff:
            visible = 100 * (hi - cutoff) / max(hi - lo, 1)
            say_ok(f"{name}: partly inside ({visible:.0f}% of its span is visible)")
        else:
            say_ok(f"{name}: fully inside the window")


def freshness_skew(bounds: dict) -> None:
    """All five sources are written by one run, so their newest documents should
    be minutes apart. Hours apart means part of a load was rejected while the
    rest landed - which is silent, and leaves the demo half-updated."""
    say_step("Were all the sources loaded together?")
    newest = {name: hi for name, (count, lo, hi) in bounds.items()
              if count and hi and name.startswith(("traces-", "logs-", "agent-metrics"))}
    if len(newest) < 2:
        return
    latest = max(newest.values())
    stale = {n: (latest - hi) / 3_600_000 for n, hi in newest.items() if (latest - hi) > 3_600_000}
    if not stale:
        say_ok("every source has data from the same run")
        return
    for name, gap in sorted(stale.items(), key=lambda kv: -kv[1]):
        say_warn(f"{name}: {gap:.1f}h older than the newest source")
    problems.append("sources are from different runs - one dataset was rejected while the others "
                    "landed. Rebuild cleanly with: make reload")


def blocks_and_disk(os_: OS) -> None:
    """A full disk flips indices read-only and every write is rejected. That
    looks like 'N documents were rejected' and nothing else explains it."""
    say_step("Write blocks and disk")
    settings = os_.get("_all/_settings", params={"filter_path": "*.settings.index.blocks"}, ok=(200, 404))
    blocked = []
    if isinstance(settings, dict):
        for index, body in settings.items():
            found = body.get("settings", {}).get("index", {}).get("blocks", {})
            if any(str(v).lower() == "true" for v in found.values()):
                blocked.append(f"{index} ({', '.join(f'{k}={v}' for k, v in found.items())})")
    if blocked:
        for item in blocked[:6]:
            say_warn(f"write-blocked: {item}")
        problems.append("indices are write-blocked (usually a full disk) - free space, then: "
                        "curl -XPUT localhost:9200/_all/_settings -H 'Content-Type: application/json' "
                        "-d '{\"index.blocks.read_only_allow_delete\": null}'")
    else:
        say_ok("no write blocks set")

    allocation = os_.get("_cat/allocation", params={"format": "json", "bytes": "b"}, ok=(200, 404))
    if isinstance(allocation, list):
        for node in allocation:
            total = int(node.get("disk.total") or 0)
            avail = int(node.get("disk.avail") or 0)
            if not total:
                continue
            used_pct = 100 * (total - avail) / total
            line = f"disk {used_pct:.0f}% used, {avail / 1e9:.1f} GB free"
            if used_pct >= 90:
                say_warn(f"{line} - the 90% high watermark is where OpenSearch starts refusing")
                problems.append("disk is above the 90% watermark - free space or use PROFILE=lite")
            else:
                say_ok(line)


def duplicates(os_: OS) -> None:
    """A second `make load` appends rather than replaces. Nothing errors; every
    count in the demo is just silently doubled. This is what that looks like."""
    say_step("Has the data been loaded more than once?")
    total = os_.count("agent-metrics-1m")
    if not total:
        return

    # One metric row per (minute, agent, tool). If rows outnumber distinct
    # minute+agent pairs by a clean multiple, the load ran more than once.
    distinct = os_.search("agent-metrics-1m", {
        "size": 0,
        "aggs": {"minutes": {"cardinality": {"field": "@timestamp"}},
                 "agents": {"cardinality": {"field": "gen_ai.agent.id"}}},
    }, ok=(200, 404))
    minutes = distinct.get("aggregations", {}).get("minutes", {}).get("value", 0) if isinstance(distinct, dict) else 0
    agents = distinct.get("aggregations", {}).get("agents", {}).get("value", 0) if isinstance(distinct, dict) else 0
    say(f"    {total:,} metric rows across ~{minutes:,} distinct minutes and {agents:,} agents")

    probe = os_.search("agent-metrics-1m", {
        "size": 0,
        "aggs": {"key": {"multi_terms": {"terms": [
            {"field": "gen_ai.agent.id"}, {"field": "gen_ai.tool.name"}],
            "size": 1, "order": {"_count": "desc"}},
            "aggs": {"slots": {"cardinality": {"field": "@timestamp"}}}}},
    }, ok=(200, 400, 404))
    buckets = probe.get("aggregations", {}).get("key", {}).get("buckets", []) if isinstance(probe, dict) else []
    if buckets:
        top = buckets[0]
        rows, slots = top["doc_count"], top["slots"]["value"]
        ratio = rows / max(slots, 1)
        say(f"    busiest agent+tool pair: {rows:,} rows over {slots:,} distinct minutes  "
            f"(ratio {ratio:.2f})")
        if ratio > 1.4:
            say_warn(f"that ratio should be ~1.00 - the data looks loaded about {round(ratio)}x over")
            problems.append(f"data appears loaded ~{round(ratio)}x - run: make reload")
        else:
            say_ok("one row per minute per agent per tool, as expected")


def panel_queries(os_: OS, state: dict) -> None:
    """The four dashboard panels, as DSL. If these return rows but the panels do
    not, the problem is the index pattern in Dashboards, not the data."""
    say_step("The four dashboard panels, run directly against the cluster")
    poison = state.get("poison_hash")
    checks = [
        ("patient zero, the metronome", "traces-agent-demo",
         {"bool": {"filter": [{"term": {"gen_ai.agent.id": "cw-runner-118"}},
                              {"term": {"gen_ai.tool.name": "http_fetch"}}]}}),
        ("everyone who read the README", "traces-agent-demo",
         {"exists": {"field": "context.hash"}}),
        ("harness policy violations", "traces-agent-demo",
         {"bool": {"filter": [{"term": {"gen_ai.operation.name": "execute_tool"}}],
                   "should": [
                       {"bool": {"must_not": [{"terms": {"gen_ai.tool.name": [
                           "read_file", "write_file", "git_push", "http_fetch"]}}]}},
                       {"bool": {"filter": [{"term": {"http.request.method": "POST"}},
                                            {"prefix": {"url.path": "/health"}}]}}],
                   "minimum_should_match": 1}}),
        ("cloud API calls by agent", "logs-sec-cloudtrail",
         {"term": {"event.dataset": "cloudtrail"}}),
    ]
    empty_traces = 0
    for label, index, query in checks:
        try:
            hits = os_.search(index, {"size": 0, "query": query}, ok=(200, 404))
            total = hits.get("hits", {}).get("total", {}).get("value", 0) if isinstance(hits, dict) else 0
        except OpenSearchError as exc:
            say_warn(f"{label:<32s} query failed: HTTP {exc.status}")
            continue
        (say_ok if total else say_warn)(f"{label:<32s} {total:>8,} hits")
        if not total and index == "traces-agent-demo":
            empty_traces += 1

    if poison:
        agents = os_.search("traces-agent-demo", {"size": 0,
                            "query": {"term": {"context.hash": poison}},
                            "aggs": {"a": {"cardinality": {"field": "gen_ai.agent.id"}}}}, ok=(200, 404))
        n = agents.get("aggregations", {}).get("a", {}).get("value", 0) if isinstance(agents, dict) else 0
        (say_ok if n else say_warn)(f"{'agents sharing the poison hash':<32s} {n:>8,}")

    if empty_traces == 3:
        problems.append("all three traces-agent panels are empty at the cluster level too - "
                        "the data is missing, not the dashboard")
    elif empty_traces == 0:
        say("\n    All four return rows here. If the dashboard still shows 'No results found',")
        say("    the index pattern in Dashboards has no cached field list. Fix with:")
        say("        python3 bin/dashboards.py")


def resolution(os_: OS) -> None:
    say_step("Do the index patterns resolve?")
    for pattern in ["traces-agent-*", "logs-sec-*", "agent-metrics-*"]:
        resolved = os_.get(f"_resolve/index/{pattern}", ok=(200, 404))
        if not isinstance(resolved, dict):
            continue
        streams = [d["name"] for d in resolved.get("data_streams", [])]
        indices = [i["name"] for i in resolved.get("indices", [])]
        if streams or indices:
            say_ok(f"{pattern:<18s} -> {', '.join(streams + indices)}")
        else:
            say_warn(f"{pattern:<18s} -> nothing")
            problems.append(f"index pattern {pattern} resolves to nothing")


def demo_state(os_: OS, state: dict) -> None:
    say_step("What the demo thinks it has")
    if not state:
        say_warn(".demo-state.json is missing - run: python3 bin/detect.py")
        problems.append(".demo-state.json is missing")
        return
    for key in ["poison_hash", "monitor_id", "policy_monitor_id", "detector_id", "sa_detector_id", "agent_id"]:
        value = state.get(key)
        say(f"    {key:<20s} {value if value else '(not set)'}")

    detector_id = state.get("detector_id") or find_detector_id(os_)
    if not detector_id:
        say_warn("no anomaly detector found in the cluster either - run: python3 bin/detect.py")
        problems.append("no anomaly detector exists")
        return
    if not state.get("detector_id"):
        say_warn(f"state is missing detector_id, but the cluster has one: {detector_id}. "
                 f"Repair with: python3 bin/detect.py --skip-ad")
        problems.append("detector_id missing from .demo-state.json")
    total = result_count(os_, detector_id)
    (say_ok if total else say_warn)(f"anomaly results for that detector: {total:,}")
    if not total:
        problems.append("the detector has produced no results - run: python3 bin/detect.py")


def main() -> int:
    os_ = OS()
    say(f"\n  Chasing shadows :: diagnose -> {os_.url}")
    os_.wait_until_ready(60)
    state = load_state()

    bounds = inventory(os_)
    time_window(bounds)
    freshness_skew(bounds)
    blocks_and_disk(os_)
    duplicates(os_)
    resolution(os_)
    panel_queries(os_, state)
    demo_state(os_, state)

    say_step("Verdict")
    if not problems:
        say("    Nothing wrong at the cluster level. The demo should run.")
        say("    Next: make verify")
        return 0
    for item in problems:
        say(f"    - {item}")
    say("")
    return 1


if __name__ == "__main__":
    sys.exit(main())
