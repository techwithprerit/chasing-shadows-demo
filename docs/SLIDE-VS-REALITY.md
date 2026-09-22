# Slide vs reality

Everything in this repo runs. Where a slide payload would not run as written,
this is what changed and why. Ordered roughly by how likely it is to come up in
Q&A — the first five are the ones somebody in the audience will know.

Each item says what the slide claims, what OpenSearch actually does, what the
demo does instead, and whether the slide needs an edit.

---

## 1 · There is no `enrich` processor in OpenSearch — slide 16

**Slide:** `{ "enrich": { "policy_name": "asset-owner", "field": "cloud.instance.id",
"target_field": "asset", "max_matches": 1 } }`

**Reality:** OpenSearch has no `enrich` ingest processor and no `_enrich/policy`
API. That is an Elasticsearch feature that did not come across the fork. Posting
this pipeline returns a 400; calling `_enrich/policy` returns `no handler found`.
The full OpenSearch 3.x processor list is `append, bytes, community_id, convert,
copy, csv, date, date_index_name, dissect, dot_expander, drop, fail, fingerprint,
foreach, geoip, geojson-feature, grok, gsub, html_strip, ip2geo, join, json, kv,
lowercase, ml_inference, pipeline, remove, remove_by_pattern, rename, script,
set, sort, sparse_encoding, split, text_chunking, text_embedding,
text_image_embedding, trim, uppercase, urldecode, user_agent`.

**What the demo does:** the asset inventory lives in the `asset-owner` index and
`bin/bootstrap.py` compiles it into a `script` processor's `params`. Ownership is
still resolved once, at write time — which is the actual point of the slide —
without a processor that does not exist.

**Other honest options:** carry ownership on the span from the collector; use
Data Prepper's `translate` processor; or resolve it at query time, which is the
thing the slide is arguing against.

**Slide edit:** yes. Swap the `enrich` processor for the `script` processor in
`config/40-pipeline-sec-normalise.json`. "Enrichment is cheap at write time"
survives intact; only the mechanism changes.

---

## 2 · `fingerprint` takes `hash_method`, and the value is version-suffixed — slide 16

**Slide:** `{ "fingerprint": { "fields": [...], "target_field": "context.hash",
"method": "SHA-1" } }`

**Reality:** the parameter is `hash_method`, not `method`, and the accepted
values are `MD5@2.16.0`, `SHA-1@2.16.0`, `SHA-256@2.16.0`, `SHA3-256@2.16.0`.
A bare `"SHA-1"` is rejected. Elasticsearch uses `method` with bare values, which
is where the slide's form comes from. The processor arrived in OpenSearch 2.16.

**What the demo does:** `"hash_method": "SHA-1@2.16.0"` on both fingerprints.

**Slide edit:** yes, one line each for `flow.id` and `context.hash`. Worth doing —
this is the field the whole incident-response story hangs on, and someone will
copy it off the slide.

---

## 3 · An ingest script cannot hold a 10-call window — slide 17

**Slide:** "Same trick for `agent-pace-cv`: a stateful script keyed on `agent.id`
over a 10-call window."

**Reality:** ingest processors are stateless per document. A Painless script
processor sees one document and nothing else — no cross-document state, no
keyed windows. There is nowhere to keep the previous nine gaps.

**What the demo does:** the collector carries the last ten inter-call gaps on the
span as `agent.recent_gaps_ms`; the script reduces them to `agent.pace_cv` and
`agent.tool_rate`; a `remove` processor drops the array before the document is
written. Same field, same cost, and the window genuinely exists somewhere.

**The version that really is stateful:** Data Prepper's `aggregate` processor
holds windowed state keyed on a field, which is exactly the shape the slide
describes. If you want the slide to stay as-is, move that computation to Data
Prepper and say so — it is a stronger answer than the ingest pipeline anyway,
and `docs/RUNBOOK.md` sketches the pipeline config.

**Slide edit:** reword. "A stateful script" → "the collector carries the gap
window; twelve lines of Painless turn it into a number." One sentence.

---

## 4 · Index Rollup renames your fields, and expects you to query the old names — slides 18, 21

**Slide 18** creates `_plugins/_rollup/jobs/agent-metrics-1m`; **slide 21** points
the detector at `agent-metrics-1m` with `category_field: ["gen_ai.agent.id"]` and
features on `http.request.body.size.sum` and `agent.pace_cv.min`.

**Reality:** a rollup target index does not store your field names. It stores
`@timestamp.date_histogram`, `gen_ai.agent.id.terms`, `http.request.body.size.sum`,
`.min`, `.max`, `.value_count`, plus `rollup._id` and `_doc_count`. `avg` is not
stored at all — the job decomposes it into `sum` + `value_count` and recomputes
it at read time, so there is no `.avg` field. The plugin installs a search
interceptor so that a hand-written search against the target index uses the
*original* field names and gets rewritten. So slide 21's feature fields happen to
line up, but `category_field: ["gen_ai.agent.id"]` would need to be
`gen_ai.agent.id.terms` if anything reads the index directly rather than through
the interceptor.

**What the demo does:** uses **Index Transform** (`_plugins/_transform`) instead.
A transform lets you name every output field, so the aggregations are named
`http.request.body.size.sum`, `agent.pace_cv.min`, `tool_calls.value_count` and
the groups target `@timestamp` / `gen_ai.agent.id` / `gen_ai.tool.name` — which
means **slide 21's detector payload runs verbatim, unchanged**. The target index
holds ordinary documents that any plugin can read without interception.

The slide-18 rollup job is still in the repo at
`config/61-rollup-agent-metrics-1m.json` and `python3 bin/bootstrap.py
--with-rollup` creates it, writing to `agent-metrics-1m-rollup` so the two cannot
collide.

**Slide edit:** optional. Either keep Rollup on the slide and add "query it with
your original field names; the plugin rewrites them", or switch the slide to
Transform. Transform is the more defensible choice for anything a detector reads.

---

## 5 · The arithmetic on slide 2 contradicts slides 3 and 4

**Slide 2:** `features: bytes_out=51.2MB/10m tool_call_cv=0.03 distinct_dst=1`

**Slide 3:** "Volume inside the daily quota."

**Slide 4:** "This one fetched every thirty seconds, 4 KB each way, for six hours."

**The problem:** 4 KB every 30 seconds is 8 KB a minute — 80 KB per ten minutes,
not 51.2 MB. To move 51.2 MB in ten minutes at 4 KB a chunk the agent would need
about 22 calls a second, which is not "every thirty seconds" and is emphatically
not "inside the daily quota" (it works out to roughly 7.4 GB a day from one
runner). Somebody will do this arithmetic.

It also undercuts the thesis. The whole argument of the talk is that the volume
was unremarkable and the *shape* was the signal — "We had no rule for 'too
regular'". A 51.2 MB spike is exactly the thing every existing rule already
catches, which would make the story about a missing volume threshold rather than
about `agent.pace_cv`.

**What the demo does:** patient zero moves 4,096 bytes every 30 seconds. Over an
hour that is 120 calls and 491,520 bytes. The monitor thresholds on
`params._count > 60 && params.cv < 0.10 && params.out > 200000` across a two-hour
window — the count and the regularity do the work, and the byte floor only
excludes noise. Nothing benign comes close: the next-highest `(agent, host)` pair
reaches about ten calls, with a pacing CV above 0.25.

**Slide edit:** recommended. Change slide 2 to `bytes_out=82KB/10m` (or
`491KB/1h`, which matches the monitor window). Everything else on the slide
stands, and the "volume inside the daily quota" line on slide 3 starts agreeing
with it.

---

## 6 · `http.request.body: {enabled: false}` also disables `http.request.body.size` — slide 14 vs 18/21/22

**Slide 14** turns the request body off with `"http.request.body": { "enabled":
false }`. **Slides 18, 21 and 22** all aggregate on `http.request.body.size`.

**Reality:** `enabled: false` on an object means its contents are stored in
`_source` but nothing underneath it is indexed or given doc values. `size` would
be inside that object, so the `sum` on slides 21 and 22 would return nothing.

**What the demo does:** `http.request.body` is an ordinary object with two
children — `size` (a real `long`, indexed, aggregatable) and `content` (`text`,
`index: false`, `doc_values: false`). The bytes story is unchanged: the payload
is stored and never indexed.

**Slide edit:** yes. `"http.request.body.content": { "index": false }` instead of
disabling the parent.

---

## 7 · `value_count` on `spanId` contradicts turning off its doc values — slide 14 vs 22

**Slide 14:** `"trace.spanId": { "type": "keyword", "doc_values": false }`, with
the note "Span IDs are looked up, never aggregated — no doc values."

**Slide 22:** `"n": { "value_count": { "field": "spanId" } }`.

**Reality:** `value_count` needs doc values. The monitor would fail or return
zero. The two slides are each right on their own and wrong together.

**What the demo does:** drops the aggregation entirely and uses `params._count`
from the composite bucket, which is free and already there.

**Slide edit:** yes, and it makes slide 22 shorter. Slide 14's note is the
correct instinct; slide 22 just needs to honour it.

---

## 8 · A bucket-level trigger needs `parent_bucket_path` and `buckets_path` — slide 22

**Slide:** `"condition": { "script": { "source": "params.n > 60 && ..." } }`

**Reality:** a `bucket_level_trigger` condition requires `parent_bucket_path`
(naming the composite aggregation, here `pair`) and `buckets_path` (mapping every
name the script uses to an aggregation). Without them the monitor will not save.

**What the demo does:**

```json
"condition": {
  "parent_bucket_path": "pair",
  "buckets_path": { "_count": "_count", "out": "out", "cv": "cv" },
  "script": { "lang": "painless",
              "source": "params._count > 60 && params.cv < 0.10 && params.out > 200000" }
}
```

Also worth knowing: `dryrun` on `_execute` is a **query parameter**, not a body
field — `POST _plugins/_alerting/monitors/<id>/_execute?dryrun=true`.

**Slide edit:** yes. Three extra lines, and the slide becomes copy-pasteable.

---

## 9 · PPL `join` is gated behind the Calcite engine — slide 23

**Slide 23's** second hunt uses `join on gen_ai.agent.id = agent.id
logs-sec-cloudtrail`.

**Reality:** `join`, `lookup` and `subsearch` arrived in PPL 3.0 and are powered
by Apache Calcite. `plugins.calcite.enabled` defaults to **false on 3.0 through
3.2** and only defaults to true from 3.3.0. On 3.0–3.2 the query fails until you
run:

```
PUT _plugins/_query/settings
{ "transient": { "plugins.calcite.enabled": true } }
```

`inner`, `left`, `outer`, `semi` and `anti` joins work once it is on; `right`,
`full` and `cross` additionally need `plugins.calcite.all_join_types.allowed`.

**What the demo does:** `bin/bootstrap.py` sets `plugins.calcite.enabled` as a
persistent cluster setting, and `bin/demo.py` tries the join first and falls back
to a two-query form that answers the same question if it is refused. `make verify`
tells you which path you are on before you go on stage.

**Slide edit:** no, but know the setting. If someone asks "does that work out of
the box", the honest answer is "on 3.3 and later".

---

## 10 · A detector carries one log type, and Sigma has no `|notin` — slide 20

Three separate things on this slide:

**(a) `gen_ai.tool.name|notin:`** is not a Sigma modifier. The allow-list has to
be a second selection, negated in the condition:

```yaml
detection:
  selection:
    Operation: execute_tool
  allowed_tools:
    ToolName: [read_file, write_file, git_push, http_fetch]
  condition: selection and not allowed_tools
```

**(b) The pre-packaged `aws_console_login_no_mfa` rule** belongs to the
`cloudtrail` log type. A detector has exactly one `detector_type`, so it cannot
sit in an `others_application` detector alongside the agent rules. It needs its
own CloudTrail detector.

**(c) The field-mapping step is missing.** Between creating the rules and
creating the detector you must call `POST _plugins/_security_analytics/mappings`
to create field aliases. Skip it and the detector matches nothing and reports no
error — the single most common reason a custom detector looks broken.

Because those mappings are **aliases**, a rule field name may not equal an
existing field name. That is why the Sigma rules in this repo say `ToolName` and
`Operation` rather than `gen_ai.tool.name` and `gen_ai.operation.name`.

**What the demo does:** valid Sigma, the mapping step, `others_application` only,
and `detection/alerting/monitor-tool-outside-policy.json` as a fallback that
produces the same finding from the same data if any of it misbehaves on the day.

**Slide edit:** the `|notin` line, yes. The pre-packaged rule, drop it or move it
to its own detector. The mapping step is worth a sentence.

---

## 11 · `zstd_no_dict` is not supported for Security Analytics indexes — slide 12 vs 20

`zstd` and `zstd_no_dict` have been GA since 2.9 and need no feature flag, and
`index.codec.compression_level` (1–6) applies only to them and the `qat_*`
codecs. But the docs state they cannot be used for k-NN or **Security Analytics**
indexes.

The demo sets `zstd_no_dict` on `traces-agent-*`, which is also what the Security
Analytics detector reads. It worked in testing; if findings stop appearing, set
`CODEC=best_compression` in `.env` and re-run `make bootstrap && make reload`.
`make verify` will tell you which layer is unhappy.

---

## 12 · ML Commons needs three settings before the connector will create — slide 24

On a single-node demo cluster:

- `plugins.ml_commons.only_run_on_ml_node: false` — otherwise model deployment
  fails with nowhere to place the model. Set in `docker-compose.yml` and again as
  a persistent setting.
- `plugins.ml_commons.trusted_connector_endpoints_regex` must allow the Bedrock
  runtime host, or connector creation is rejected outright.
- A `conversational` agent **requires** `llm.parameters.response_filter`, and its
  value is model-specific — `$.content[0].text` for the Bedrock Anthropic
  Messages shape.

The tool type names on the slide are all correct: `PPLTool`,
`SearchAnomalyResultsTool`, `SearchIndexTool`.

---

## 13 · Smaller things worth knowing

- **`shingle_size`** is accepted by the create-detector API even though the API
  reference's parameter table omits it and only shows it in responses. It is
  parsed and defaults to 8. If someone says "that's not in the docs", it is in
  the source.
- **`category_field`** accepts at most **two** fields.
- **Historical analysis** is the same `_start` endpoint with `start_time` and
  `end_time` in the body. It returns a task id and produces results in seconds
  instead of waiting out `shingle_size × detection_interval` of wall clock. This
  is the only reason the detector is demoable in an eight-minute slot.
- **HC detector results** carry an `entity` array of `{name, value}`; filter on
  `entity.value` for per-agent grades.
- **Bulk into a data stream** must use the `create` action, not `index`.
- **`_note` keys**: every JSON file in this repo carries them as inline
  documentation. `bin/bootstrap.py` strips them recursively before sending,
  because OpenSearch would reject them as unknown parameters. If you lift a
  payload straight out of a file into Dev Tools, delete the `_note` first.
