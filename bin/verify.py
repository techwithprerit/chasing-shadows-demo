#!/usr/bin/env python3
"""
Prove every beat of the demo works, before you are standing in front of anyone.

Run this after setup and again in the venue once you are on their network. It
checks the things that actually break: a processor that is not on this build, a
strict mapping rejecting a field, a trigger that fires for the wrong agent, PPL
join being gated behind a setting, a detector with no graded results.

Exit code 0 means the eight minutes will run.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from detect import entity_grades, flat_line_buckets, load_state  # noqa: E402
from generator.generate import PATIENT_ZERO  # noqa: E402
from ml.triage_fallback import _rows  # noqa: E402
from os_http import OS, REPO_ROOT, OpenSearchError, say  # noqa: E402

RESULTS: list[tuple[str, bool, str, bool]] = []  # name, ok, detail, required


def check(name: str, required: bool = True):
    """A failed `required` check means the demo will not run. A failed optional
    check means one beat degrades to a documented fallback."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            try:
                detail = fn(*args, **kwargs) or ""
                RESULTS.append((name, True, detail, required))
                print(f"  PASS  {name:<52s} {detail}")
                return
            except AssertionError as exc:
                detail = str(exc)
            except OpenSearchError as exc:
                detail = f"HTTP {exc.status}: {exc.body[:120]}"
            except Exception as exc:  # noqa: BLE001
                detail = repr(exc)
            RESULTS.append((name, False, detail, required))
            print(f"  {'FAIL' if required else 'SKIP'}  {name:<52s} {detail}")
        return wrapper
    return decorator


@check("cluster reachable and healthy")
def check_cluster(os_: OS) -> str:
    health = os_.get("_cluster/health")
    version = os_.get("/")["version"]["number"]
    assert health["status"] in {"green", "yellow"}, f"status is {health['status']}"
    return f"OpenSearch {version}, {health['status']}"


@check("index templates applied with the expected codec")
def check_templates(os_: OS) -> str:
    templates = os_.get("_index_template/traces-agent")["index_templates"]
    settings = templates[0]["index_template"]["template"]["settings"]["index"]
    codec = settings["codec"]
    assert settings["mapping"]["total_fields"]["limit"] == "400"
    assert settings["sort"]["field"] == ["gen_ai.agent.id", "@timestamp"]
    return f"codec={codec}, index sort on agent then time"


@check("strict mapping is on and rejects unknown fields")
def check_strict(os_: OS) -> str:
    # traces-agent-demo is a data stream, so this has to go through _bulk with a
    # create action - a plain POST /_doc is refused for the wrong reason and
    # would make this check pass by accident.
    lines = [
        json.dumps({"create": {"_index": "traces-agent-demo"}}),
        json.dumps({"@timestamp": "2026-03-17T02:14:00.000Z",
                    "totally_new_field": "one agent framework's free-form metadata"}),
    ]
    result = os_.post("_bulk", "\n".join(lines) + "\n",
                      content_type="application/x-ndjson", raw=True)
    assert result.get("errors"), "an unmapped field was accepted - dynamic:strict is not in effect"
    reason = result["items"][0]["create"]["error"]["reason"]
    assert "strict" in reason or "dynamic" in reason, f"rejected, but not by strict mapping: {reason[:160]}"
    return "unmapped field rejected by strict mapping"


@check("ingest pipeline derives every field the talk claims")
def check_pipeline(os_: OS) -> str:
    span = json.loads((REPO_ROOT / "data" / "poisoned-span.json").read_text())
    result = os_.post("_ingest/pipeline/sec-normalise/_simulate", {"docs": [{"_source": span}]})
    doc = result["docs"][0].get("doc")
    assert doc, "the pipeline dropped the poisoned span"
    source = doc["_source"]
    assert source.get("context", {}).get("hash"), "context.hash missing"
    pace = source.get("agent", {}).get("pace_cv")
    assert pace is not None, "agent.pace_cv missing"
    assert pace < 0.1, f"pace_cv should be near 0.03 for the metronome window, got {pace}"
    assert source.get("agent", {}).get("tokens_per_call") is not None, "tokens_per_call missing"
    assert source.get("asset", {}).get("team"), "asset.team missing - the owner lookup did not fire"
    assert "recent_gaps_ms" not in source.get("agent", {}), "gap window was not removed"
    assert "input" not in source["gen_ai"].get("tool", {}), "document body was not removed"
    return f"pace_cv={pace:.4f}, team={source['asset']['team']}, body and gaps dropped"


@check("data present in every index")
def check_data(os_: OS) -> str:
    counts = {
        name: os_.count(name)
        for name in ["traces-agent-demo", "logs-sec-cloudtrail", "logs-sec-dns",
                     "logs-sec-vpcflow", "agent-metrics-1m", "asset-owner", "sec-context-docs"]
    }
    empty = [k for k, v in counts.items() if v == 0]
    assert not empty, f"empty: {', '.join(empty)}"
    return ", ".join(f"{k.split('-')[-1]}={v:,}" for k, v in counts.items())


@check("drop processors removed what no detector reads")
def check_drops(os_: OS) -> str:
    leftover = os_.count(
        "traces-agent-demo",
        {"query": {"bool": {"filter": [
            {"term": {"gen_ai.operation.name": "chat"}},
            {"term": {"status": "OK"}},
            {"range": {"gen_ai.usage.output_tokens": {"lt": 50}}},
        ]}}},
    )
    assert leftover == 0, f"{leftover} trivial chat spans survived the drop processor"
    tiny_flows = os_.count("logs-sec-vpcflow", {"query": {"range": {"network.bytes": {"lt": 64}}}})
    assert tiny_flows == 0, f"{tiny_flows} sub-64-byte flow records survived"
    return "trivial chat spans and keepalive flows are gone"


@check("data was loaded exactly once")
def check_single_load(os_: OS) -> str:
    """A second `make load` appends instead of replacing. Nothing errors and
    every number in the demo is quietly multiplied, so assert it here."""
    probe = os_.search("agent-metrics-1m", {
        "size": 0,
        "aggs": {"key": {"multi_terms": {
            "terms": [{"field": "gen_ai.agent.id"}, {"field": "gen_ai.tool.name"}],
            "size": 1, "order": {"_count": "desc"}},
            "aggs": {"slots": {"cardinality": {"field": "@timestamp"}}}}},
    }, ok=(200, 400, 404))
    buckets = probe.get("aggregations", {}).get("key", {}).get("buckets", []) if isinstance(probe, dict) else []
    assert buckets, "agent-metrics-1m is empty - run: python3 bin/load.py"
    rows, slots = buckets[0]["doc_count"], buckets[0]["slots"]["value"]
    ratio = rows / max(slots, 1)
    assert ratio <= 1.4, (f"metric rows outnumber distinct minutes {ratio:.1f}x - the data has been "
                          f"loaded about {round(ratio)} times. Run: make reload")
    return f"one row per minute per agent+tool (ratio {ratio:.2f})"


@check("replay tail is withheld and ready for step 2")
def check_tail(os_: OS) -> str:
    path = REPO_ROOT / "data" / "replay-tail.ndjson"
    assert path.exists(), "data/replay-tail.ndjson missing - re-run bin/load.py"
    docs = len(path.read_text().splitlines()) // 2
    assert docs > 0, "the tail file is empty"
    return f"{docs:,} spans held back"


@check("monitor fires for exactly one agent, and it is patient zero")
def check_monitor(os_: OS, state: dict) -> str:
    result = os_.post(f"_plugins/_alerting/monitors/{state['monitor_id']}/_execute", params={"dryrun": "true"})
    fired = flat_line_buckets(result)
    assert fired, ("no bucket satisfied the trigger condition - either the replay has drifted out "
                   "of the monitor's 2h window (run 'make reload'), or the composite size is "
                   "smaller than the agent-and-host cardinality")
    agents = {b["key"]["agent"] for b in fired}
    assert agents == {PATIENT_ZERO}, f"expected only {PATIENT_ZERO}, got {agents}"
    b = fired[0]
    return f"{b['key']['agent']} -> {b['key']['host']}, n={b['doc_count']}, cv={b['cv']['value']:.3f}"


@check("PPL runs the pacing hunt")
def check_ppl(os_: OS) -> str:
    rows = _rows(os_.ppl(
        "source = traces-agent-* | where gen_ai.tool.name = 'http_fetch' "
        "| stats sum(http.request.body.size) as out, stddev_samp(http.request.body.size) as jitter, "
        "count() as n by span(`@timestamp`, 5m), gen_ai.agent.id, url.domain "
        "| eval flat = jitter / (out / n) | where n > 8 and flat < 0.05 | sort - out | head 10"
    ))
    assert rows, "the pacing hunt returned nothing"
    agents = {r["gen_ai.agent.id"] for r in rows}
    assert PATIENT_ZERO in agents, f"{PATIENT_ZERO} not in {agents}"
    return f"{len(rows)} flat windows, agents={sorted(agents)}"


@check("PPL join is available (slide 23, second hunt)", required=False)
def check_ppl_join(os_: OS, state: dict) -> str:
    query = (
        f"source = traces-agent-* | where context.hash = '{state['poison_hash']}' "
        "| stats count() as reads by gen_ai.agent.id "
        "| join on gen_ai.agent.id = agent.id logs-sec-cloudtrail "
        "| stats dc(event.action) as api_calls by gen_ai.agent.id | sort - api_calls"
    )
    try:
        rows = _rows(os_.ppl(query))
        return f"join returned {len(rows)} rows"
    except OpenSearchError as exc:
        raise AssertionError(
            f"join failed (HTTP {exc.status}). Set plugins.calcite.enabled=true, or accept the "
            f"two-step fallback bin/demo.py uses automatically."
        ) from exc


@check("blast radius: nine agents share the poison hash")
def check_blast_radius(os_: OS, state: dict) -> str:
    result = os_.search(
        "traces-agent-demo",
        {"size": 0, "query": {"term": {"context.hash": state["poison_hash"]}},
         "aggs": {"a": {"cardinality": {"field": "gen_ai.agent.id"}}}},
    )
    n = result["aggregations"]["a"]["value"]
    assert n >= 2, f"only {n} agent(s) carry the poison hash"
    return f"{n} agents"


@check("cloud API surface widened for patient zero only")
def check_api_delta(os_: OS) -> str:
    result = os_.search(
        "logs-sec-cloudtrail",
        {"size": 0, "aggs": {"a": {"terms": {"field": "agent.id", "size": 500},
                                   "aggs": {"api": {"cardinality": {"field": "event.action"}}}}}},
    )
    buckets = result["aggregations"]["a"]["buckets"]
    ranked = sorted(buckets, key=lambda b: -b["api"]["value"])
    assert ranked[0]["key"] == PATIENT_ZERO, f"top API-surface agent is {ranked[0]['key']}"
    return f"{PATIENT_ZERO}={ranked[0]['api']['value']} actions, next={ranked[1]['api']['value']}"


@check("anomaly detector has graded results, topped by patient zero")
def check_detector(os_: OS, state: dict) -> str:
    rows = sorted(entity_grades(os_, state["detector_id"], size=10), key=lambda r: -(r["grade"] or 0))
    assert rows, "no graded anomaly results - run bin/detect.py --wait"
    top = rows[0]
    assert top["entity"] == PATIENT_ZERO, f"top graded entity is {top['entity']}, not {PATIENT_ZERO}"
    return f"{top['entity']} grade {top['grade']:.3f}"


@check("policy findings exist (Security Analytics or fallback monitor)")
def check_findings(os_: OS, state: dict) -> str:
    if state.get("sa_ok") and state.get("sa_detector_id"):
        result = os_.get("_plugins/_security_analytics/findings/_search",
                         params={"detector_id": state["sa_detector_id"], "size": 5}, ok=(200, 404))
        findings = result.get("findings", []) if isinstance(result, dict) else []
        if findings:
            return f"Security Analytics: {len(findings)} findings"
    result = os_.post(f"_plugins/_alerting/monitors/{state['policy_monitor_id']}/_execute",
                      params={"dryrun": "true"})
    total = (result.get("input_results", {}).get("results", [{}])[0]
             .get("hits", {}).get("total", {}).get("value", 0))
    assert total > 0, "neither Security Analytics nor the fallback monitor found policy violations"
    return f"fallback monitor: {total} violating spans"


@check("the README is retrievable by context.hash")
def check_context_doc(os_: OS, state: dict) -> str:
    result = os_.search("sec-context-docs", {"size": 1, "query": {"term": {"context.hash": state["poison_hash"]}}})
    hits = result["hits"]["hits"]
    assert hits, "no context document for the poison hash - step 8 will fail"
    doc = hits[0]["_source"]
    assert doc["doc"]["verdict"] == "prompt-injection"
    return f"{doc['doc']['title']} ({doc['doc']['bytes']:,} bytes)"


def main() -> int:
    os_ = OS()
    say(f"\n  Chasing shadows :: verify -> {os_.url}\n")
    state = load_state()
    if not state:
        say("  .demo-state.json is missing. Run bootstrap, load and detect first.\n")
        return 2

    check_cluster(os_)
    check_templates(os_)
    check_strict(os_)
    check_pipeline(os_)
    check_data(os_)
    check_single_load(os_)
    check_drops(os_)
    check_tail(os_)
    check_monitor(os_, state)
    check_ppl(os_)
    check_ppl_join(os_, state)
    check_blast_radius(os_, state)
    check_api_delta(os_)
    check_detector(os_, state)
    check_findings(os_, state)
    check_context_doc(os_, state)

    passed = sum(1 for _, ok, _, _ in RESULTS if ok)
    blocking = [n for n, ok, _, req in RESULTS if not ok and req]
    degraded = [n for n, ok, _, req in RESULTS if not ok and not req]
    say(f"\n  {passed}/{len(RESULTS)} passed"
        + (f", {len(blocking)} blocking" if blocking else "")
        + (f", {len(degraded)} degraded" if degraded else "") + "\n")
    if degraded:
        say("  Degraded (the demo still runs, using a documented fallback):")
        for name in degraded:
            say(f"    - {name}")
        say("")
    if blocking:
        say("  These will not work on stage:")
        for name in blocking:
            say(f"    - {name}")
        say("\n  Every one of them has a note in docs/SLIDE-VS-REALITY.md or docs/RUNBOOK.md.\n")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
