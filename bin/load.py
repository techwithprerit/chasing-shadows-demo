#!/usr/bin/env python3
"""
Generate the incident and index it.

The one interesting step here is resolving context.hash. The hash that ties
nine agents to one poisoned README is produced by the fingerprint processor
inside the cluster, not by this script - so we run the poisoned span through
_ingest/pipeline/sec-normalise/_simulate first, read the hash the cluster
computed, and hand that to the generator. Nothing is hard-coded, and what the
demo shows in step 1 is the same value that is in the data.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from os_http import ENV, OS, REPO_ROOT, say, say_ok, say_step, say_warn  # noqa: E402
from generator.generate import (  # noqa: E402
    INDEX_FOR,
    PATIENT_ZERO,
    PROFILES,
    Generator,
    iso,
    to_ndjson,
)

BATCH = 2000


def resolve_poison_hash(os_: OS, gen: Generator) -> str:
    say_step("Resolving context.hash from the cluster")
    span = gen.poisoned_span_for_simulate()
    result = os_.post("_ingest/pipeline/sec-normalise/_simulate", {"docs": [{"_source": span}]})
    doc = result["docs"][0].get("doc")
    if not doc:
        raise SystemExit(f"pipeline dropped the poisoned span during simulate:\n{json.dumps(result, indent=2)}")
    source = doc["_source"]
    context_hash = source.get("context", {}).get("hash")
    if not context_hash:
        raise SystemExit(
            "the fingerprint processor did not produce context.hash. Check that this build "
            "accepts hash_method 'SHA-1@2.16.0' (OpenSearch 2.16+):\n" + json.dumps(source, indent=2)[:2000]
        )
    say_ok(f"context.hash = {context_hash}")
    say_ok(f"agent.pace_cv = {source.get('agent', {}).get('pace_cv')}  (computed from the collector's gap window)")
    return context_hash


def bulk_load(os_: OS, docs: list, index: str, op: str, label: str, tally: dict) -> tuple[int, int]:
    if not docs:
        return 0, 0
    sent = failures = 0
    started = time.time()
    for offset in range(0, len(docs), BATCH):
        chunk = docs[offset : offset + BATCH]
        lines = []
        for doc in chunk:
            lines.append(json.dumps({op: {"_index": index}}))
            lines.append(json.dumps(doc, separators=(",", ":")))
        failures += os_.bulk(lines, tally=tally)
        sent += len(chunk)
        done = offset + len(chunk)
        pct = 100 * done / len(docs)
        print(f"\r    {label:22s} {done:>8,}/{len(docs):,}  ({pct:5.1f}%)", end="", flush=True)
    elapsed = time.time() - started
    rate = sent / elapsed if elapsed else 0
    print(f"\r    {label:22s} {sent:>8,} sent  {failures:>5,} failed  {elapsed:6.1f}s  ({rate:,.0f} docs/s)")
    return sent, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default=ENV.get("PROFILE", "stage"), choices=sorted(PROFILES))
    parser.add_argument("--seed", type=int, default=int(ENV.get("SEED", "118")))
    parser.add_argument("--keep-files", action="store_true",
                        help="also write data/*.ndjson so you can show the replay file on stage")
    parser.add_argument("--fresh", action="store_true", help="delete existing demo data first")
    parser.add_argument("--append", action="store_true",
                        help="load on top of existing data. Almost never what you want - it "
                             "doubles every count the demo reports.")
    args = parser.parse_args()

    os_ = OS()
    say(f"Chasing shadows :: load ({args.profile}) -> {os_.url}")
    os_.wait_until_ready()

    if args.fresh:
        say_step("Clearing previous run")
        for target in ["_data_stream/traces-agent-demo", "_data_stream/logs-sec-cloudtrail",
                       "_data_stream/logs-sec-dns", "_data_stream/logs-sec-vpcflow"]:
            os_.delete(target)
        for index in ["agent-metrics-1m", "sec-context-docs", "asset-owner"]:
            os_.delete(index)
        say_ok("data streams and lookup indices removed (templates and pipelines are untouched)")
        # Lookup indices are created by bootstrap; recreate them here so --fresh
        # does not require a second bootstrap run.
        import bootstrap
        bootstrap.plain_indices(os_)

    # Loading twice into the same data streams silently doubles everything: the
    # monitor's call counts, the metric rows the detector reads, the PPL totals.
    # Nothing errors, the numbers are just wrong. Refuse instead.
    if not args.fresh and not args.append:
        existing = {name: os_.count(name) for name in
                    ["traces-agent-demo", "logs-sec-cloudtrail", "logs-sec-dns",
                     "logs-sec-vpcflow", "agent-metrics-1m"]}
        already = {k: v for k, v in existing.items() if v}
        if already:
            say_step("This cluster already has demo data")
            for name, count in already.items():
                say(f"    {name:<24s} {count:>10,} documents")
            say("")
            say("  Loading again would append, not replace - every count in the demo would be")
            say("  wrong, and the detector would read two rows for every minute. Use:")
            say("")
            say("      make reload          # wipe the data and load it cleanly")
            say("")
            say("  or, if you really do want to add a second copy on top:")
            say("")
            say("      python3 bin/load.py --append")
            say("")
            return 2

    gen_probe = Generator(args.profile, args.seed, "PROBE")
    poison_hash = resolve_poison_hash(os_, gen_probe)

    say_step("Generating the replay")
    started = time.time()
    gen = Generator(args.profile, args.seed, poison_hash)
    data = gen.build()
    say_ok(f"{gen.stats['spans']:,} spans, {gen.stats['metrics']:,} metric rows in {time.time() - started:.1f}s")
    say_ok(f"patient zero {PATIENT_ZERO} goes metronome at {iso(gen.incident_start)}")
    say_ok(f"poison readers: {', '.join(sorted(a.id for a in gen.poison_readers))}")

    # bin/demo.py needs these two on disk: step 1 simulates the poisoned span
    # and step 2 bulks the withheld tail. Written every run, not just --keep-files.
    out_dir = REPO_ROOT / "data"
    out_dir.mkdir(exist_ok=True)
    tail_index, tail_op = INDEX_FOR["traces_tail"]
    (out_dir / "replay-tail.ndjson").write_text(to_ndjson(data["traces_tail"], tail_index, tail_op))
    (out_dir / "poisoned-span.json").write_text(json.dumps(gen.poisoned_span_for_simulate(), indent=2))
    say_ok(f"withheld {len(data['traces_tail']):,} spans for demo step 2 -> data/replay-tail.ndjson")

    if args.keep_files:
        for key, docs in data.items():
            if key == "traces_tail":
                continue
            index, op = INDEX_FOR[key]
            (out_dir / f"{index}.ndjson").write_text(to_ndjson(docs, index, op))
        say_ok(f"full bulk files written to {out_dir}")

    say_step("Indexing")
    tally: dict = {}
    totals = {}
    # Count before, count after: the drop is the difference between what we sent
    # and what actually landed THIS run, never a raw index total.
    before = {name: os_.count(name) for name in ["traces-agent-demo", "logs-sec-vpcflow", "agent-metrics-1m"]}
    for key in ["assets", "context_docs", "traces", "cloudtrail", "dns", "vpcflow", "metrics"]:
        index, op = INDEX_FOR[key]
        sent, failed = bulk_load(os_, data[key], index, op, key, tally)
        totals[key] = (sent, failed)

    say_step("Refreshing")
    os_.post("_refresh")
    time.sleep(2)

    # The gap between what we sent and what landed is the drop processors doing
    # their job: trivial chat spans and sub-64-byte flow records.
    say_step("What the pipeline kept")
    for label, key, index in [("agent spans", "traces", "traces-agent-demo"),
                              ("vpc flow", "vpcflow", "logs-sec-vpcflow")]:
        sent = totals[key][0]
        landed = os_.count(index) - before[index]
        dropped = max(sent - landed, 0)
        say(f"    {label:<15s} sent {sent:>8,}   indexed {landed:>8,}   "
            f"dropped {dropped:>7,}  ({100 * dropped / max(sent, 1):.1f}%)")
    say(f"    agent-metrics-1m                     indexed "
        f"{os_.count('agent-metrics-1m') - before['agent-metrics-1m']:>8,}")
    say("\n    Those drops are slide 16's last two processors: successful chat spans under")
    say("    50 output tokens, and flow records under 64 bytes. Nothing a detector reads.")

    failures = sum(f for _, f in totals.values())
    if failures:
        say_step("Why documents were rejected")
        for (etype, reason), count in sorted(tally.items(), key=lambda kv: -kv[1])[:6]:
            say(f"    {count:>8,}  {etype}")
            say(f"              {reason}")
        say("")
        if any("cluster_block" in e or "read_only" in r for (e, r) in tally):
            say_warn("The cluster has blocked writes - almost always the flood-stage disk "
                     "watermark. Free space, then clear it with:")
            say("      curl -XPUT localhost:9200/_all/_settings -H 'Content-Type: application/json' \\")
            say("        -d '{\"index.blocks.read_only_allow_delete\": null}'")
        else:
            say_warn(f"{failures:,} documents were rejected. A strict mapping rejects unknown "
                     "fields by design - read the reasons above before demoing.")
        return 1

    say_step("Loaded")
    say("  next:  python3 bin/detect.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
