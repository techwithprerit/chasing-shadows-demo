# Stage runbook

Eight minutes, nine steps, two flows. What to run, what to say over it, what to
do when something does not come back.

---

## The day before

```bash
make up          # pulls images; do this on a network you trust
make setup       # bootstrap + load + detect  (~6-10 min on the stage profile)
make verify      # 15 checks; nothing may be marked FAIL
make rehearse    # the whole demo end to end, no pauses
```

`make setup` is the slow part — the anomaly-detection batch task is most of it.
Nothing in the eight minutes waits on it.

## In the venue, before you are miked

```bash
make verify
```

Fifteen checks, about twenty seconds. FAIL means a step will not work on stage;
SKIP means it degrades to a documented fallback and the demo still runs (only
the PPL join is allowed to SKIP). It tells you which step will break before an
audience finds out. If the laptop slept since setup, the replay timestamps
are still relative to the load, not to now — see *The timestamps drifted* below.

## Running it

```bash
make demo                 # pauses for Enter between steps
python3 bin/demo.py --step 5      # start at Flow 02
python3 bin/demo.py --only 3      # rehearse one beat
```

---

## Flow 01 · replay → monitor → PPL   (minutes 26–30)

### Step 1 — one poisoned span through the pipeline · ~45s
`POST _ingest/pipeline/sec-normalise/_simulate`

Shows the span going in with a 1,479-byte README and ten inter-call gaps, and
coming out with `context.hash`, `agent.pace_cv` ≈ 0.03, `agent.tokens_per_call`,
`asset.team` — and *without* the document body or the gap array.

> The line to land: two derived numbers and a fingerprint, computed once at write
> time. The body and the window leave before anything is written. That is slide
> 11's second rule doing its job — store the derivative.

**If it fails:** `hash_method` is the usual culprit on an older build. `make
verify` names it. Nothing else in the demo depends on this step.

### Step 2 — bulk the withheld tail · ~20s
`POST _bulk → traces-agent-demo`

`bin/load.py` deliberately held back the last fifteen minutes of the replay, so
this is a real ingest, not a re-index. Watch the document count move.

**If the file is missing:** `python3 bin/load.py` regenerates it. If you are
short on time, skip to step 3 — the monitor still fires on what is already loaded.

### Step 3 — the monitor fires · ~45s
`POST _plugins/_alerting/monitors/<id>/_execute`

One bucket out of roughly 990 agent-and-host pairs: `cw-runner-118 →
mirror.internal`, pacing CV ~0.026. The call count runs 120–240 and the bytes
490 KB–980 KB depending on how much of the two-hour window the metronome fills,
which in turn depends on how long ago you loaded.

> The line to land: notice what is *not* in that condition — a volume threshold
> big enough to notice. 492 KB an hour sat inside the daily quota. The flat line
> is the signal.

**If nothing fires:** almost always the clock. See *The timestamps drifted*.

### Step 4 — pivot into PPL · ~2m
`POST _plugins/_ppl`

Three queries, with a pause between each:

1. **Who is a metronome** — five-minute windows where the byte size never moved.
2. **Who else read the poison** — one term query on `context.hash`, nine agents.
3. **Who moved on to the credentials** — the join, with an automatic two-step
   fallback if Calcite is off.

> The line to land: nine agents read the README. Eight were still on a different
> task. One had moved on to the credentials.

**If a query is rejected:** the driver prints the error and continues to the next
one. The third query falls back on its own. `make verify` tells you in advance
whether `join` is available on this build.

---

## Flow 02 · detector → findings   (minutes 30–33)

### Step 5 — the detector, per entity · ~40s
Per-agent grades from the historical run. `cw-runner-118` on top.

> The line to land: one RCF model per agent, about a megabyte each. shingle_size
> 8 at a 10-minute interval means the model sees an 80-minute shape — so a
> metronome is anomalous even when its volume is not.

### Step 6 — inject a scripted agent · ~2m
Writes 40 minutes of metronome-shaped one-minute rows for `cw-runner-042`, then
re-runs historical analysis and shows its grade climbing.

This is the longest step because the batch task has to run. **Talk over it** —
this is the natural place for the per-agent-model cost argument (212 models fit
in a coordinator's heap; 20,000 is a cardinality budget you pay for in
`plugins.anomaly_detection.model_max_size_percent`).

> The line to land: cw-runner-042 was invisible an hour ago, and nobody wrote a
> rule for it.

**If it takes too long:** Ctrl-C the wait and move on; step 7 does not depend on
it. Or run `--only 6` in rehearsal and screenshot the output as a backup slide.

### Step 7 — signature findings · ~40s
Security Analytics findings for the same agent, or the fallback query-level
monitor. The driver picks automatically and says which it used.

> The line to land: same agent, two independent layers — a model that graded the
> shape, and a rule that named the behaviour.

### Step 8 — finding → trace → the README · ~40s
Retrieves the poisoned document from `sec-context-docs` by `context.hash` and
prints the white-on-white paragraph.

> The line to land: the agent used only the tools it was given, against endpoints
> on its allow-list, signed by its own role. The prompt is the perimeter now.

### Step 9 — the triage agent · optional closer
Runs the registered ML Commons agent if Bedrock is configured, otherwise the
scripted four-hunt runner. Both produce the same summary and the same
recommendation, and neither can revoke anything.

> The line to land: the model writes the paragraph; the queries do the work. And
> there is no revoke tool in that tool list.

---

## When something goes wrong

### The timestamps drifted
The replay is anchored to the moment you ran `bin/load.py`. The monitor looks
back two hours and needs more than 60 calls in it, and the metronome runs at two
a minute — so the alert stops firing roughly **90 minutes** after you load the
data, and steps 3 and 4 come back empty. Reload if your slot is further away
than that.

```bash
make reload && python3 bin/detect.py --wait
```

Ten minutes on the stage profile. `make reload PROFILE=lite` is ninety seconds
and still tells the whole story with 24 agents — a fine choice if you are
reloading in the speaker room.

### `ModuleNotFoundError` on any script
Should not happen — the repo is standard library only. If it does, you are on a
Python older than 3.9; `python3 --version` and use a newer one.

### The anomaly-detection wait says "(state not reported)"
Expected on some builds: the profile endpoint is inconsistent about where it
reports a batch task. The wait falls back to watching the result count, which is
the number that matters. When results stop arriving it moves on by itself, and
`bin/demo.py` reads the results index rather than the task in any case.

### Dashboard panels say "No results found" but the data is there
Check the timestamps first, not the index pattern. `make diagnose` prints the
newest document per source; the saved dashboard looks back seven hours, so
anything older than that shows an empty panel with no error. If one source is
hours or days older than the others, part of a load was rejected while the rest
landed - `make reload` is the fix, and the rejection reasons are now printed at
the end of the load.

### A load reported thousands of rejections
The load now groups rejections by error type and prints the reason. The two that
actually happen: a full disk (OpenSearch flips indices to read-only, and
`make diagnose` reports both the block and the disk headroom), and mapping drift
on a data stream whose backing index predates a template change. `make reload`
cures the second, because it re-applies the templates *before* deleting and
recreating the streams.

### The cluster will not start
Almost always memory. OpenSearch wants 2 GB of heap plus overhead; Docker
Desktop ships with less. Raise Docker's memory to 6 GB, or set `HEAP=1g` in
`.env` and use `PROFILE=lite`.

### `make verify` fails on the detector
`python3 bin/detect.py --wait` and let the batch task finish. If it reports no
graded results afterwards, the metrics window is too short for `shingle_size`
8 — use `PROFILE=stage` or `full`, not `lite`.

### Security Analytics is unhappy
Run `python3 bin/detect.py --skip-sa`. Step 7 falls back automatically and the
narrative is unchanged; you just say "same rule, run as a monitor" instead.

### Bedrock is unreachable
Expected on conference wifi. `BEDROCK_ENABLED=false` in `.env`, and step 9 uses
the scripted runner. Arguably the better demo: it makes visible how much of
"an agent triaged it" is four queries.

### Everything is on fire and you have two minutes
```bash
python3 bin/demo.py --only 3      # the monitor fires
python3 bin/demo.py --only 4      # the PPL hunts
python3 bin/demo.py --only 8      # the README
```
Those three beats carry the argument on their own.

---

## The Data Prepper variant (for the slide-17 question)

If someone asks how you would hold a real ten-call window at ingest, this is the
answer — Data Prepper's `aggregate` processor keeps state keyed on a field, which
an OpenSearch ingest processor cannot:

```yaml
agent-traces-pipeline:
  source:
    otel_trace_source:
  processor:
    - aggregate:
        identification_keys: ["gen_ai.agent.id"]
        action:
          histogram:
            key: "agent.inter_call_gap_ms"
            units: "ms"
            buckets: [1000, 5000, 15000, 30000, 60000, 120000]
        group_duration: "600s"
  sink:
    - opensearch:
        index: traces-agent-demo
```

Not wired into this repo — it is a second process to run on stage for one field —
but it is the honest answer to "your slide said stateful".

---

## Timing sheet

| Step | Beat | Target | Slack |
|------|------|--------|-------|
| 1 | `_simulate` | 0:45 | can cut |
| 2 | `_bulk` | 0:20 | can cut |
| 3 | monitor fires | 0:45 | keep |
| 4 | three PPL hunts | 2:00 | keep two of three |
| 5 | per-entity grades | 0:40 | keep |
| 6 | inject + regrade | 2:00 | cut first if behind |
| 7 | findings | 0:40 | can cut |
| 8 | the README | 0:40 | keep |
| 9 | triage | 1:00 | optional closer |

Total with everything: about 9:30. The slot is 8:00 (minutes 26–33), so plan to
drop step 6 or step 7 and keep 3, 4 and 8 whatever happens.
