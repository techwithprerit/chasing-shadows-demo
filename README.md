# Chasing shadows with OpenSearch — the demo

The eight minutes from slide 26, as a repo you can run.

A cluster of 212 autonomous coding agents on an overnight backlog. One of them,
`cw-runner-118`, fetched a vendor README six hours ago with white-on-white
instructions buried in it, and has been a metronome ever since: `http_fetch`
every thirty seconds, 4 KB each way, one destination, coefficient of variation
0.03. Every API call signed by its own instance role. Every endpoint on its
allow-list. Zero signature hits.

This repo generates that night, ships the schema, pipelines, detectors and rules
that catch it, and drives the demo step by step.

```bash
cp .env.example .env
make up        # OpenSearch 3.x + Dashboards
make setup     # schema, pipelines, replay, detectors  (6-10 min)
make dashboards # saved objects + field lists
make verify    # 15 checks that the demo will work
make demo      # the eight minutes
```

---

## What is in here

```
config/       index templates, Painless scripts, ingest pipeline, ISM, transform, rollup
detection/    Sigma rules, Security Analytics detector, alerting monitors, AD detector
ml/           Bedrock connector, triage agent, and the scripted fallback triage runner
generator/    the incident: 212 agents, one metronome, nine poison readers
bin/          bootstrap · load · detect · verify · demo
dashboards/   saved objects for the finding -> trace -> README drilldown
docs/         WALKTHROUGH.md · RUNBOOK.md · SLIDE-VS-REALITY.md · PPL-QUERIES.md
```

Every JSON file carries `_note` keys explaining what it is and which slide it
comes from. `bin/bootstrap.py` strips them before sending, because OpenSearch
would reject them as unknown parameters.

## The scripts

| | |
|---|---|
| `bin/bootstrap.py` | cluster settings, index templates, stored scripts, ingest pipeline, ISM policy, transform job |
| `bin/load.py` | resolves `context.hash` from the cluster, generates the replay, bulk-indexes it, reports what the pipeline dropped |
| `bin/detect.py` | monitors, the anomaly detector plus its historical run, Sigma rules, Security Analytics detector, triage agent |
| `bin/verify.py` | 15 assertions covering every beat of the demo. Run it in the venue. |
| `bin/demo.py` | the nine steps, paused between each. `--only N` to rehearse one. |
| `bin/dashboards.py` | imports the saved objects and refreshes their field lists |
| `bin/diagnose.py` | read-only health report — run it when a panel or a step looks wrong |

## Profiles

`PROFILE` in `.env`, or `make setup PROFILE=lite`.

| | agents | raw spans | metrics for training | generate |
|---|---|---|---|---|
| `lite` | 24 | 2 h | 1 day | ~1 s |
| `stage` | 212 | 6 h | 2 days | ~30 s |
| `full` | 212 | 24 h | 5 days | ~2 min |

`stage` is what the demo is tuned for. `lite` is for iterating; the anomaly
detector needs `stage` or better to have enough history for `shingle_size` 8.

## What the demo shows

**Flow 01 — replay → monitor → PPL**

1. One poisoned span through `_simulate`: `context.hash` and `agent.pace_cv`
   appear, the document body and the gap window leave.
2. `_bulk` the withheld last fifteen minutes of the replay.
3. The bucket-level monitor fires for exactly one agent-and-host pair out of 212.
4. Three PPL hunts: who is a metronome, who else read the poison, and which of
   them moved on to the credentials.

**Flow 02 — detector → findings**

5. Per-entity anomaly grades, one Random Cut Forest model per agent.
6. Inject a second scripted agent and watch its grade climb across two intervals.
7. Signature findings from the Sigma rules, correlated to the same agent.
8. Finding → trace → the README that started it.
9. The triage agent runs the four hunts a human would, and recommends. It has no
   revoke tool.

## The numbers the demo produces

On the `stage` profile, with seed 118:

```
  patient zero        cw-runner-118 -> mirror.internal
  pacing CV           ~0.026         (fleet median ~0.53)
  calls in the hour   120            (next-highest agent-and-host pair: ~10)
  bytes out           491,520        inside the daily quota, which is the point
  poison readers      9 agents sharing one context.hash
  API surface         cw-runner-118: 9 distinct actions, every other reader: 3
```

The exact figures are 120 calls (two a minute for an hour) and 120 x 4,096
bytes; the CVs drift by a percent or two between runs because the replay window
is anchored to the moment you load it. `make verify` asserts the separation
rather than the digits, so a failed rehearsal tells you which property moved.

## Requirements

Docker with 6 GB available to it, and Python 3.9+. **No pip install, no
virtualenv** — every script is standard library only, so there is nothing to
argue with Homebrew's Python about five minutes before you present.

No cloud account needed — the triage agent falls back to a scripted runner that
executes the same four hunts, which is also the right choice on conference wifi.

To use the real ML Commons agent, set `BEDROCK_ENABLED=true` and the AWS
credentials in `.env`. `bin/detect.py` registers the connector, model and agent;
`bin/demo.py` falls back to the scripted runner automatically if the call fails
mid-demo.

## Before you present

**Start with `docs/WALKTHROUGH.md`** — the story, every OpenSearch concept the
demo uses explained from zero, the step-by-step script with what to say over
each beat, and the questions you will get. Read that first if you have not
presented this before.

Then **`docs/SLIDE-VS-REALITY.md`**. Thirteen places where a slide payload does
not run as written — no `enrich` processor in OpenSearch, `fingerprint` wanting
a version-suffixed `hash_method`, a bucket-level trigger needing
`parent_bucket_path`, and the arithmetic on slide 2 disagreeing with slides 3 and
4. Each one says what to change and whether the slide needs an edit.

Then **`docs/RUNBOOK.md`** for the stage timings, the line to land on each step,
and what to do when a step does not come back.

## Licence

Apache-2.0, same as OpenSearch. Take it.
