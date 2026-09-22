#!/usr/bin/env python3
"""
Stand up the four layers of detection (slide 19) against the loaded data.

  layer 1  signatures  - Security Analytics, custom Sigma rules
  layer 2  models      - Anomaly Detection, one RCF per agent
  layer 3  hunting     - the monitors that good hunts turn into
  layer 4  agents      - ML Commons triage agent, read-only

Everything it creates is recorded in .demo-state.json so bin/demo.py knows the
ids without you pasting anything. Each layer degrades on its own: if Security
Analytics will not co-operate, the equivalent query-level monitor is used and
the demo still runs.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bootstrap import payload  # noqa: E402
from generator.generate import POISON_URL  # noqa: E402
from os_http import ENV, OS, REPO_ROOT, OpenSearchError, say, say_ok, say_step, say_warn  # noqa: E402

STATE_PATH = REPO_ROOT / ".demo-state.json"
TRACE_INDEX = "traces-agent-demo"


def load_state() -> dict:
    return json.loads(STATE_PATH.read_text()) if STATE_PATH.exists() else {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2))


# --------------------------------------------------------------------------- #
def find_poison_hash(os_: OS) -> str | None:
    # registry.mirror.internal is also a benign domain every agent fetches all
    # night, so a prefix query on the domain returns mostly innocent spans. Ask
    # for the exact README URL AND the presence of the hash.
    result = os_.search(
        TRACE_INDEX,
        {
            "size": 1,
            "query": {"bool": {"filter": [
                {"term": {"url.full": POISON_URL}},
                {"exists": {"field": "context.hash"}},
            ]}},
            "_source": ["context.hash", "url.full", "gen_ai.agent.id"],
        },
        ok=(200, 404),
    )
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return None
    return hits[0]["_source"].get("context", {}).get("hash")


TERMINAL_TASK_STATES = {"FINISHED", "STOPPED", "FAILED"}


def historical_state(os_: OS, detector_id: str) -> str | None:
    """
    State of the historical batch task, or None if this build will not say.

    The profile endpoint is inconsistent about where it reports a batch task
    across versions and between single-entity and high-cardinality detectors, so
    try the documented shapes in order rather than trusting one of them.
    """
    attempts = [
        (f"_plugins/_anomaly_detection/detectors/{detector_id}/_profile", {"_all": "true"}),
        (f"_plugins/_anomaly_detection/detectors/{detector_id}/_profile/ad_task", None),
        (f"_plugins/_anomaly_detection/detectors/{detector_id}/_profile/ad_task,state", None),
    ]
    for path, params in attempts:
        profile = os_.get(path, params=params, ok=(200, 400, 404))
        if not isinstance(profile, dict):
            continue
        for key in ("ad_task", "historical_analysis_task", "realtime_task"):
            task = profile.get(key) or {}
            if isinstance(task, dict) and task.get("state"):
                return task["state"]
    return None


def result_count(os_: OS, detector_id: str) -> int:
    result = os_.post(
        "_plugins/_anomaly_detection/detectors/results/_search",
        {"size": 0, "query": {"term": {"detector_id": detector_id}}},
        ok=(200, 404),
    )
    if not isinstance(result, dict):
        return 0
    return int(result.get("hits", {}).get("total", {}).get("value", 0))


def wait_for_historical(os_: OS, detector_id: str, timeout: int = 900) -> str:
    """
    Wait for the historical analysis to finish.

    Reports the state when the cluster will give one, and falls back to watching
    the result count - which is the signal that actually matters, and is a better
    progress indicator anyway. Returns the reason it stopped waiting.
    """
    deadline = time.time() + timeout
    plateau = 0
    previous = -1
    while time.time() < deadline:
        state = historical_state(os_, detector_id)
        count = result_count(os_, detector_id)
        label = state or "(state not reported)"
        print(f"\r    {label:<24s} {count:>8,} results written", end="", flush=True)

        if state in TERMINAL_TASK_STATES:
            print()
            if state == "FAILED" or count == 0:
                say_warn(f"batch task {state.lower()} with {count:,} results. Check "
                         f"GET _plugins/_anomaly_detection/detectors/{detector_id}/_profile?_all=true")
            else:
                say_ok(f"batch task {state.lower()} with {count:,} results")
            return state

        # No state from this build: call it done when results stop arriving.
        plateau = plateau + 1 if count == previous and count > 0 else 0
        previous = count
        if plateau >= 6:  # ~30s with no new results
            print()
            say_ok(f"results stopped arriving at {count:,} - treating the batch task as complete")
            return "PLATEAU"
        time.sleep(5)

    print()
    say_warn(f"batch task still running after {timeout // 60} minutes. Results already written are "
             f"usable; bin/demo.py reads the index, not the task.")
    return "TIMEOUT"


def find_detector_id(os_: OS, name: str = "agent-egress-pace") -> str | None:
    """Look the detector up by name. .demo-state.json is a convenience, not the
    source of truth - the cluster is - so nothing should break just because the
    file is missing or was written before an interrupt."""
    result = os_.post(
        "_plugins/_anomaly_detection/detectors/_search",
        {"size": 1, "query": {"term": {"name.keyword": name}}},
        ok=(200, 404),
    )
    hits = result.get("hits", {}).get("hits", []) if isinstance(result, dict) else []
    return hits[0]["_id"] if hits else None


def ensure_detector_id(os_: OS, state: dict) -> str | None:
    """Detector id from state, falling back to a lookup and repairing state."""
    if state.get("detector_id"):
        return state["detector_id"]
    found = find_detector_id(os_)
    if found:
        state["detector_id"] = found
        save_state(state)
        say_ok(f"recovered detector id {found} from the cluster")
    return found


def entity_grades(os_: OS, detector_id: str, size: int = 12, entity: str | None = None) -> list[dict]:
    """
    Per-entity anomaly grades for a high-cardinality detector.

    The results index maps `entity` as a nested field, so a top-level terms
    aggregation on entity.value returns zero buckets with HTTP 200 - silence,
    not an error. Try the nested form first and fall back to the flat form, so
    this works whichever way the build maps it.
    """
    must = [{"term": {"detector_id": detector_id}}, {"range": {"anomaly_grade": {"gt": 0}}}]

    nested_body = {
        "size": 0,
        "query": {"bool": {"filter": must + (
            [{"nested": {"path": "entity", "query": {"term": {"entity.value": entity}}}}] if entity else []
        )}},
        "aggs": {"ent": {"nested": {"path": "entity"}, "aggs": {
            "entities": {"terms": {"field": "entity.value", "size": size},
                         "aggs": {"back": {"reverse_nested": {}, "aggs": {
                             "peak": {"max": {"field": "anomaly_grade"}},
                             "conf": {"max": {"field": "confidence"}}}}}}}}},
    }
    result = os_.post("_plugins/_anomaly_detection/detectors/results/_search", nested_body, ok=(200, 400, 404))
    buckets = (result.get("aggregations", {}).get("ent", {}).get("entities", {}).get("buckets", [])
               if isinstance(result, dict) else [])
    if buckets:
        return [{"entity": b["key"], "grade": b["back"]["peak"]["value"],
                 "confidence": b["back"]["conf"]["value"], "findings": b["back"]["doc_count"]}
                for b in buckets]

    flat_body = {
        "size": 0,
        "query": {"bool": {"filter": must + ([{"term": {"entity.value": entity}}] if entity else [])}},
        "aggs": {"entities": {"terms": {"field": "entity.value", "size": size},
                              "aggs": {"peak": {"max": {"field": "anomaly_grade"}},
                                       "conf": {"max": {"field": "confidence"}}}}},
    }
    result = os_.post("_plugins/_anomaly_detection/detectors/results/_search", flat_body, ok=(200, 400, 404))
    buckets = (result.get("aggregations", {}).get("entities", {}).get("buckets", [])
               if isinstance(result, dict) else [])
    return [{"entity": b["key"], "grade": b["peak"]["value"],
             "confidence": b["conf"]["value"], "findings": b["doc_count"]} for b in buckets]


def flat_line_buckets(execute_result: dict) -> list[dict]:
    """
    Buckets from a monitor _execute response that satisfy the flat-line
    condition. Walks EVERY entry in input_results.results, not just the first -
    the composite aggregation can span more than one result set, and patient
    zero sorts about halfway down the agent id range.
    """
    fired = []
    for entry in execute_result.get("input_results", {}).get("results", []) or []:
        for bucket in entry.get("aggregations", {}).get("pair", {}).get("buckets", []) or []:
            if (bucket.get("doc_count", 0) > 60
                    and bucket.get("cv", {}).get("value", 1) < 0.10
                    and bucket.get("out", {}).get("value", 0) > 200000):
                fired.append(bucket)
    return fired


def upsert_monitor(os_: OS, path: str, state_key: str, state: dict) -> str:
    body = payload(path)
    existing = os_.post(
        "_plugins/_alerting/monitors/_search",
        {"query": {"term": {"monitor.name.keyword": body["name"]}}},
        ok=(200, 404),
    )
    hits = existing.get("hits", {}).get("hits", []) if isinstance(existing, dict) else []
    if hits:
        monitor_id = hits[0]["_id"]
        os_.put(f"_plugins/_alerting/monitors/{monitor_id}", body)
        say_ok(f"updated monitor '{body['name']}'  id={monitor_id}")
    else:
        created = os_.post("_plugins/_alerting/monitors", body)
        monitor_id = created["_id"]
        say_ok(f"created monitor '{body['name']}'  id={monitor_id}")
    state[state_key] = monitor_id
    return monitor_id


def monitors(os_: OS, state: dict) -> None:
    say_step("Layer 3 - alerting monitors")
    upsert_monitor(os_, "detection/alerting/monitor-flat-line.json", "monitor_id", state)
    upsert_monitor(os_, "detection/alerting/monitor-tool-outside-policy.json", "policy_monitor_id", state)


# --------------------------------------------------------------------------- #
def anomaly_detector(os_: OS, state: dict, *, wait: bool) -> None:
    say_step("Layer 2 - anomaly detection (one RCF model per agent)")
    body = payload("detection/anomaly-detection/detector-agent-egress-pace.json")

    existing = os_.post(
        "_plugins/_anomaly_detection/detectors/_search",
        {"query": {"term": {"name.keyword": body["name"]}}},
        ok=(200, 404),
    )
    hits = existing.get("hits", {}).get("hits", []) if isinstance(existing, dict) else []
    if hits:
        detector_id = hits[0]["_id"]
        seq, term = hits[0]["_seq_no"], hits[0]["_primary_term"]
        os_.put(
            f"_plugins/_anomaly_detection/detectors/{detector_id}",
            body,
            params={"if_seq_no": seq, "if_primary_term": term},
        )
        say_ok(f"updated detector '{body['name']}'  id={detector_id}")
    else:
        created = os_.post("_plugins/_anomaly_detection/detectors", body)
        detector_id = created["_id"]
        say_ok(f"created detector '{body['name']}'  id={detector_id}")
    state["detector_id"] = detector_id
    # Persist NOW, not after the wait. Interrupting the batch task must not lose
    # the id - that is what left step 6 posting to /detectors/None/_start.
    save_state(state)

    # Historical analysis over the window we just loaded. This is what makes the
    # detector usable in an eight-minute slot: results in seconds instead of
    # waiting out shingle_size x detection_interval of wall clock.
    bounds = os_.search(
        "agent-metrics-1m",
        {"size": 0, "aggs": {"lo": {"min": {"field": "@timestamp"}}, "hi": {"max": {"field": "@timestamp"}}}},
        ok=(200, 404),
    )
    lo_value = bounds.get("aggregations", {}).get("lo", {}).get("value") if isinstance(bounds, dict) else None
    hi_value = bounds.get("aggregations", {}).get("hi", {}).get("value") if isinstance(bounds, dict) else None
    if lo_value is None or hi_value is None:
        say_warn("agent-metrics-1m is empty - run bin/load.py before bin/detect.py")
        return
    lo, hi = int(lo_value), int(hi_value)
    say_ok(f"metrics window spans {(hi - lo) / 3_600_000:.1f} hours")

    started = os_.post(
        f"_plugins/_anomaly_detection/detectors/{detector_id}/_start",
        {"start_time": lo, "end_time": hi},
    )
    task_id = started.get("_id")
    state["ad_task_id"] = task_id
    save_state(state)
    say_ok(f"historical analysis started  task={task_id}")

    if not wait:
        say_warn("not waiting for the batch task; run bin/detect.py --wait before you go on stage")
        return

    say("    waiting for the batch task (this is the slow part of setup, not of the demo)")
    wait_for_historical(os_, detector_id, timeout=900)

    rows = sorted(entity_grades(os_, detector_id, size=5), key=lambda r: -(r["grade"] or 0))
    if rows:
        say_ok("top graded entities:")
        for row in rows:
            say(f"      {row['entity']:18s} max grade {row['grade']:.3f}  ({row['findings']} findings)")
    else:
        say_warn("no graded results yet - the models may still be warming up")


# --------------------------------------------------------------------------- #
def backing_indices(os_: OS) -> list[str]:
    stream = os_.get(f"_data_stream/{TRACE_INDEX}", ok=(200, 404))
    entries = stream.get("data_streams", []) if isinstance(stream, dict) else []
    if entries:
        return [i["index_name"] for i in entries[0]["indices"]]
    return [TRACE_INDEX]


def security_analytics(os_: OS, state: dict) -> None:
    say_step("Layer 1 - Security Analytics (custom Sigma rules)")
    rule_ids = []
    for filename in ["agent_tool_outside_policy.yml", "agent_role_token_in_body.yml"]:
        yaml_body = (REPO_ROOT / "detection" / "sigma" / filename).read_text()
        try:
            created = os_.post(
                "_plugins/_security_analytics/rules",
                yaml_body,
                content_type="application/yaml",
                params={"category": "others_application"},
                raw=True,
            )
            rule_ids.append(created["_id"])
            say_ok(f"rule {filename} -> {created['_id']}")
        except OpenSearchError as exc:
            say_warn(f"rule {filename} rejected ({exc.status}): {exc.body[:220]}")

    if len(rule_ids) < 2:
        say_warn("falling back to the query-level monitor for policy findings")
        state["sa_ok"] = False
        return
    state["rule_ids"] = rule_ids

    mapping_body = payload("detection/security-analytics/field-mappings.json")
    mapped_any = False
    for index in backing_indices(os_):
        body = dict(mapping_body, index_name=index)
        try:
            os_.post("_plugins/_security_analytics/mappings", body)
            say_ok(f"field aliases applied to {index}")
            mapped_any = True
        except OpenSearchError as exc:
            say_warn(f"alias mapping failed for {index} ({exc.status}): {exc.body[:220]}")

    if not mapped_any:
        say_warn("no field aliases were applied; a detector would match nothing. Using the fallback monitor.")
        state["sa_ok"] = False
        return

    detector_body = payload(
        "detection/security-analytics/detector-agent-harness.json",
        {"__INDEX__": TRACE_INDEX, "__RULE_ID_1__": rule_ids[0], "__RULE_ID_2__": rule_ids[1]},
    )
    try:
        created = os_.post("_plugins/_security_analytics/detectors", detector_body)
        detector_id = created["_id"]
        state["sa_detector_id"] = detector_id
        state["sa_ok"] = True
        say_ok(f"detector 'agent-harness' created  id={detector_id}")
        say("    findings appear within a schedule period (1 minute)")
    except OpenSearchError as exc:
        say_warn(f"detector rejected ({exc.status}): {exc.body[:300]}")
        state["sa_ok"] = False


# --------------------------------------------------------------------------- #
def triage_agent(os_: OS, state: dict) -> None:
    say_step("Layer 4 - triage agent")
    if str(ENV.get("BEDROCK_ENABLED", "false")).lower() not in {"1", "true", "yes"}:
        say_ok("BEDROCK_ENABLED=false - bin/demo.py will use the scripted triage runner "
               "(ml/triage_fallback.py), which executes the same four hunts")
        state["agent_id"] = None
        return

    missing = [k for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY") if not ENV.get(k)]
    if missing:
        say_warn(f"BEDROCK_ENABLED=true but {', '.join(missing)} is empty - falling back to the scripted runner")
        state["agent_id"] = None
        return

    try:
        connector = payload(
            "ml/connector-bedrock-claude.json",
            {
                "__AWS_ACCESS_KEY_ID__": ENV["AWS_ACCESS_KEY_ID"],
                "__AWS_SECRET_ACCESS_KEY__": ENV["AWS_SECRET_ACCESS_KEY"],
                "__AWS_SESSION_TOKEN__": ENV.get("AWS_SESSION_TOKEN", ""),
                "__AWS_REGION__": ENV.get("AWS_REGION", "us-west-2"),
                "__BEDROCK_MODEL_ID__": ENV.get("BEDROCK_MODEL_ID", ""),
            },
        )
        connector_id = os_.post("_plugins/_ml/connectors/_create", connector)["connector_id"]
        say_ok(f"connector {connector_id}")

        registered = os_.post(
            "_plugins/_ml/models/_register",
            {
                "name": "bedrock-claude-sec-triage",
                "function_name": "remote",
                "description": "Bedrock Claude for sec-triage",
                "connector_id": connector_id,
            },
            params={"deploy": "true"},
        )
        model_id = registered.get("model_id")
        if not model_id:  # async registration returns a task
            task_id = registered["task_id"]
            for _ in range(40):
                task = os_.get(f"_plugins/_ml/tasks/{task_id}")
                if task.get("state") == "COMPLETED":
                    model_id = task["model_id"]
                    break
                if task.get("state") == "FAILED":
                    raise OpenSearchError("GET", "tasks", 500, json.dumps(task))
                time.sleep(3)
        say_ok(f"model {model_id} deployed")

        agent_body = payload("ml/agent-sec-triage.json", {"__MODEL_ID__": model_id})
        agent_id = os_.post("_plugins/_ml/agents/_register", agent_body)["agent_id"]
        state.update(agent_id=agent_id, model_id=model_id, connector_id=connector_id)
        say_ok(f"agent 'sec-triage' registered  id={agent_id}")
        say("    read-only tools only: PPLTool, SearchAnomalyResultsTool, SearchIndexTool. No revoke tool exists.")
    except OpenSearchError as exc:
        say_warn(f"Bedrock path failed ({exc.status}): {exc.body[:300]}")
        say_warn("bin/demo.py will use the scripted triage runner instead - the demo is unaffected")
        state["agent_id"] = None


# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wait", action="store_true", default=True,
                        help="wait for the anomaly-detection batch task (default)")
    parser.add_argument("--no-wait", dest="wait", action="store_false")
    parser.add_argument("--skip-sa", action="store_true", help="skip Security Analytics entirely")
    parser.add_argument("--skip-ad", action="store_true",
                        help="leave the anomaly detector alone - use this to finish setup after "
                             "interrupting the batch task, without starting another one")
    args = parser.parse_args()

    os_ = OS()
    say(f"Chasing shadows :: detect -> {os_.url}")
    os_.wait_until_ready()

    state = load_state()
    poison_hash = find_poison_hash(os_)
    if not poison_hash:
        raise SystemExit("no traces found - run bin/load.py first")
    state["poison_hash"] = poison_hash
    say_ok(f"poison context.hash = {poison_hash}")

    try:
        return _run(os_, state, args)
    except KeyboardInterrupt:
        save_state(state)
        say("")
        say_warn("interrupted - state saved. Resume with: python3 bin/detect.py --skip-ad")
        return 130


def _run(os_: OS, state: dict, args) -> int:
    monitors(os_, state)
    save_state(state)

    if args.skip_ad:
        say_step("Layer 2 - anomaly detection")
        detector_id = ensure_detector_id(os_, state)
        if detector_id:
            say_ok(f"skipping (--skip-ad); detector {detector_id} has "
                   f"{result_count(os_, detector_id):,} results")
        else:
            say_warn("skipping (--skip-ad), but no detector exists yet - re-run without the flag")
    else:
        anomaly_detector(os_, state, wait=args.wait)
    save_state(state)

    if not args.skip_sa:
        security_analytics(os_, state)
        save_state(state)

    triage_agent(os_, state)
    save_state(state)

    say_step("Detection ready")
    say(f"  state written to {STATE_PATH.name}")
    say("  next:  python3 bin/verify.py    # prove every step of the demo works")
    say("         python3 bin/demo.py      # run it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
