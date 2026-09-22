#!/usr/bin/env python3
"""
Apply every piece of cluster configuration the demo needs, in order.

Idempotent: run it as many times as you like. Nothing here depends on data
existing yet - detectors and rules that need a populated index live in
bin/detect.py, which runs after bin/load.py.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from os_http import ENV, OS, OpenSearchError, dump, load_json, say, say_ok, say_step, say_warn  # noqa: E402
from generator.generate import PROFILES, Generator  # noqa: E402


def strip_notes(obj):
    """Remove every _note key. They exist so the repo reads like documentation;
    OpenSearch would reject them as unknown parameters."""
    if isinstance(obj, dict):
        return {k: strip_notes(v) for k, v in obj.items() if k != "_note"}
    if isinstance(obj, list):
        return [strip_notes(v) for v in obj]
    return obj


def substitute(obj, mapping: dict):
    """Replace __TOKEN__ placeholders, including whole-value object swaps."""
    if isinstance(obj, dict):
        return {k: substitute(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute(v, mapping) for v in obj]
    if isinstance(obj, str) and obj in mapping:
        return mapping[obj]
    return obj


def payload(relative_path: str, mapping: dict | None = None):
    return substitute(strip_notes(load_json(relative_path)), mapping or {})


# --------------------------------------------------------------------------- #
def cluster_settings(os_: OS) -> None:
    say_step("Cluster settings")
    settings = {
        "persistent": {
            # PPL join / lookup / subsearch are Calcite-backed and the engine is
            # off by default on 3.0-3.2. Slide 23's second hunt needs it.
            "plugins.calcite.enabled": True,
            "plugins.calcite.fallback.allowed": True,
            # Single-node demo: no dedicated ML node exists to place a model on.
            "plugins.ml_commons.only_run_on_ml_node": False,
            "plugins.ml_commons.native_memory_threshold": 99,
            "plugins.ml_commons.agent_framework_enabled": True,
            "plugins.ml_commons.trusted_connector_endpoints_regex": [
                "^https://bedrock-runtime\\..*[a-z0-9-]\\.amazonaws\\.com/.*$"
            ],
        }
    }
    try:
        os_.put("_cluster/settings", settings)
        say_ok("calcite enabled, ML Commons relaxed for single-node")
    except OpenSearchError as exc:
        # Older builds reject unknown setting keys outright; apply what we can.
        say_warn(f"batch settings rejected ({exc.status}); applying individually")
        for key, value in settings["persistent"].items():
            try:
                os_.put("_cluster/settings", {"persistent": {key: value}})
                say_ok(key)
            except OpenSearchError:
                say_warn(f"{key} not supported on this build - skipping")


def index_templates(os_: OS, codec: str) -> None:
    say_step("Index templates")
    mapping = {"__CODEC__": codec}
    for name, path in [
        ("traces-agent", "config/10-index-template-traces-agent.json"),
        ("logs-sec", "config/11-index-template-logs-sec.json"),
        ("agent-metrics", "config/12-index-template-agent-metrics.json"),
    ]:
        os_.put(f"_index_template/{name}", payload(path, mapping))
        say_ok(f"_index_template/{name}  (codec={codec})")


def plain_indices(os_: OS) -> None:
    say_step("Lookup indices")
    for name, path in [
        ("sec-context-docs", "config/13-index-sec-context-docs.json"),
        ("asset-owner", "config/14-index-asset-owner.json"),
    ]:
        try:
            os_.put(name, payload(path))
            say_ok(f"created {name}")
        except OpenSearchError as exc:
            if "resource_already_exists" in exc.body:
                say_ok(f"{name} already exists")
            else:
                raise


def stored_scripts(os_: OS) -> None:
    say_step("Stored Painless scripts")
    for script_id, path in [
        ("shannon-entropy", "config/20-script-shannon-entropy.json"),
        ("agent-pace-cv", "config/21-script-agent-pace-cv.json"),
        ("tokens-per-call", "config/22-script-tokens-per-call.json"),
    ]:
        os_.put(f"_scripts/{script_id}", payload(path))
        say_ok(f"_scripts/{script_id}")


def ingest_pipeline(os_: OS, owners: dict) -> None:
    say_step("Ingest pipeline")
    body = payload("config/40-pipeline-sec-normalise.json", {"__ASSET_OWNERS__": owners})

    if not os_.has_processor("community_id"):
        say_warn("community_id processor unavailable (needs OpenSearch 2.13+) - substituting a fingerprint flow key. "
                 "Note this is a flow identifier, not a spec-compliant Community ID.")
        fallback = {
            "fingerprint": {
                "fields": ["source.ip", "destination.ip", "source.port", "destination.port", "network.transport"],
                "target_field": "network.community_id",
                "hash_method": "SHA-1@2.16.0",
                "ignore_missing": True,
                "ignore_failure": True,
                "if": "ctx.source?.ip != null && ctx.destination?.ip != null",
            }
        }
        body["processors"] = [fallback if "community_id" in p else p for p in body["processors"]]

    os_.put("_ingest/pipeline/sec-normalise", body)
    say_ok(f"_ingest/pipeline/sec-normalise  ({len(body['processors'])} processors, {len(owners)} assets in the owner map)")


def ism_policy(os_: OS) -> None:
    say_step("ISM policy")
    body = payload("config/50-ism-sec-tiers.json")
    try:
        existing = os_.get("_plugins/_ism/policies/sec-tiers", ok=(200, 404))
        if existing.get("_id"):
            os_.put(
                "_plugins/_ism/policies/sec-tiers",
                body,
                params={"if_seq_no": existing["_seq_no"], "if_primary_term": existing["_primary_term"]},
            )
        else:
            os_.put("_plugins/_ism/policies/sec-tiers", body)
        say_ok("_plugins/_ism/policies/sec-tiers  (hot 3d -> warm 30d -> cold 90d -> delete)")
    except OpenSearchError as exc:
        say_warn(f"ISM policy not applied: {exc.status}. Cold state needs a registered snapshot repository.")

    repos = os_.get("_snapshot", ok=(200, 404))
    if "s3-sec" not in (repos or {}):
        say_warn("snapshot repository 's3-sec' is not registered - the cold state cannot run. "
                 "Run 'make snapshot-repo' to register a local filesystem repo under that name.")


def transform_job(os_: OS) -> None:
    say_step("Index transform (1-minute agent rollup)")
    body = payload("config/60-transform-agent-metrics-1m.json")
    try:
        os_.put("_plugins/_transform/agent-metrics-1m", body)
        say_ok("_plugins/_transform/agent-metrics-1m created (not started; bin/load.py writes the same "
               "shape directly so the demo never waits on a batch job)")
    except OpenSearchError as exc:
        say_warn(f"transform job not created: {exc.status} - the demo does not depend on it")


def rollup_job(os_: OS) -> None:
    say_step("Index rollup (slide 18, optional)")
    body = payload("config/61-rollup-agent-metrics-1m.json")
    try:
        os_.put("_plugins/_rollup/jobs/agent-metrics-1m", body)
        say_ok("_plugins/_rollup/jobs/agent-metrics-1m created -> agent-metrics-1m-rollup")
        say_warn("Query it with ORIGINAL field names; the plugin rewrites them. See docs/SLIDE-VS-REALITY.md item 4.")
    except OpenSearchError as exc:
        say_warn(f"rollup job not created: {exc.status}")


# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=ENV.get("PROFILE", "stage"), choices=sorted(PROFILES))
    parser.add_argument("--seed", type=int, default=int(ENV.get("SEED", "118")))
    parser.add_argument("--codec", default=ENV.get("CODEC", "zstd_no_dict"))
    parser.add_argument("--with-rollup", action="store_true", help="also create the slide-18 rollup job")
    args = parser.parse_args()

    os_ = OS()
    say(f"Chasing shadows :: bootstrap -> {os_.url}")
    os_.wait_until_ready()

    cluster_settings(os_)
    index_templates(os_, args.codec)
    plain_indices(os_)
    stored_scripts(os_)

    # The asset inventory is deterministic for a given profile+seed, so the
    # owner map the pipeline uses and the rows bin/load.py indexes agree.
    gen = Generator(args.profile, args.seed, "BOOTSTRAP")
    owners = {a["cloud"]["instance"]["id"]: [a["asset"]["owner"], a["asset"]["team"], a["asset"]["criticality"]]
              for a in gen.asset_inventory()}
    ingest_pipeline(os_, owners)

    ism_policy(os_)
    transform_job(os_)
    if args.with_rollup:
        rollup_job(os_)

    say_step("Bootstrap complete")
    say("  next:  python3 bin/load.py        # generate and index the incident")
    say("         python3 bin/detect.py      # detectors, rules, historical analysis")
    say("         python3 bin/demo.py        # the eight minutes on stage")
    return 0


if __name__ == "__main__":
    sys.exit(main())
