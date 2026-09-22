# The hunts

Every query in the demo, plus the ones that did not fit on a slide. Run them in
Dashboards → Query Workbench, or:

```bash
curl -s localhost:9200/_plugins/_ppl -H 'Content-Type: application/json' \
  -d '{"query":"source = traces-agent-* | head 5"}' | python3 -m json.tool
```

Two syntax notes that will cost you five minutes otherwise: `@timestamp` needs
backticks because of the `@`, and `join` / `lookup` / `subsearch` need
`plugins.calcite.enabled: true` on OpenSearch 3.0–3.2 (default from 3.3).

---

## 1 · Who is a metronome?

Slide 23, left. Real agents think, fetch, write, wait — their request sizes and
their pacing both move. A script's do not.

```sql
source = traces-agent-*
| where gen_ai.tool.name = 'http_fetch'
| stats sum(http.request.body.size) as out,
        stddev_samp(http.request.body.size) as jitter,
        count() as n
  by span(`@timestamp`, 5m), gen_ai.agent.id, url.domain
| eval flat = jitter / (out / n)
| where n > 8 and flat < 0.05
| sort - out
| head 20
```

`flat` is the coefficient of variation of the *payload size*. A chunker sending
fixed 4 KB blocks has jitter 0, so `flat` is 0. Anything doing real work is well
above 0.05.

## 2 · Who is a metronome, by pacing rather than payload?

The same question against the field that was computed at write time. Cheaper,
and it catches a chunker that varies its block size.

```sql
source = traces-agent-*
| where gen_ai.operation.name = 'execute_tool'
| stats avg(agent.pace_cv) as pace, count() as n, dc(url.domain) as hosts
  by gen_ai.agent.id
| where n > 40 and pace < 0.15
| sort pace
| head 20
```

## 3 · Who else read the poison?

Slide 23, right. One term query on a fingerprint computed at write time. This is
the query that turns a six-hour incident into a fifty-two-minute one.

```sql
source = traces-agent-*
| where context.hash = '<hash>'
| stats count() as reads, min(`@timestamp`) as first_seen
  by gen_ai.agent.id, session.id
| sort - reads
```

Get the hash from `.demo-state.json`, or:

```sql
source = sec-context-docs | where doc.verdict = 'prompt-injection' | fields context.hash, url.full
```

## 4 · Which of them moved on to the credentials?

The join. Nine agents read the README; the one that matters is the one whose
cloud API surface widened afterwards.

```sql
source = traces-agent-*
| where context.hash = '<hash>'
| stats count() as reads by gen_ai.agent.id
| join on gen_ai.agent.id = agent.id logs-sec-cloudtrail
| stats dc(event.action) as api_calls by gen_ai.agent.id
| sort - api_calls
```

**Two-step form** if Calcite is off — same answer, no join:

```sql
source = logs-sec-cloudtrail
| where agent.id in ('cw-runner-118', 'cw-runner-021', ...)
| stats dc(event.action) as api_calls by agent.id
| sort - api_calls
```

`bin/demo.py` falls back to this automatically.

## 5 · What exactly did it start calling?

```sql
source = logs-sec-cloudtrail
| where agent.id = 'cw-runner-118'
| stats count() as calls, min(`@timestamp`) as first_seen by event.action
| sort - calls
```

The rows that appear only after the incident start are the escalation:
`secretsmanager:GetSecretValue`, `kms:Decrypt`, `sts:AssumeRole`.

## 6 · Tunnelling, as a range query rather than a regex

Slide 13. `dns.entropy` was computed by twelve lines of Painless at write time,
so finding high-entropy labels is a range query somebody can type at 03:00.

```sql
source = logs-sec-dns
| where dns.entropy > 3.5
| stats count() as queries, avg(dns.entropy) as entropy, dc(dns.question.name) as names
  by agent.id
| sort - queries
```

## 7 · Token burn against bytes moved

Slide 13's argument for `agent.tokens_per_call`: exfiltration is cheap in tokens.
An agent moving bytes without spending tokens is not reasoning about anything.

```sql
source = traces-agent-*
| where gen_ai.operation.name = 'execute_tool' and gen_ai.tool.name = 'http_fetch'
| stats sum(http.request.body.size) as bytes_out,
        avg(agent.tokens_per_call) as tokens
  by gen_ai.agent.id
| eval bytes_per_token = bytes_out / tokens
| where bytes_out > 100000
| sort - bytes_per_token
| head 10
```

## 8 · Novel destinations for a task type

`url.novelty` is set at the edge on the first sighting of a host+path for a task
type. First contact is the cheapest thing to alert on and the easiest to forget
to store.

```sql
source = traces-agent-*
| where url.novelty > 0
| stats count() as first_contacts by task.type, url.domain
| sort - first_contacts
| head 20
```

## 9 · Tool mix drift per task type

Slide 13: the tool mix for a task type is a stable baseline, and drift is a
finding.

```sql
source = traces-agent-*
| where gen_ai.operation.name = 'execute_tool'
| stats count() as calls by task.type, gen_ai.tool.name
| sort task.type, - calls
```

Anything outside `read_file`, `write_file`, `git_push`, `http_fetch` is a
harness-policy violation — the Sigma rule on slide 20, expressed as a hunt.

## 10 · Blast radius with the owner attached

Ties the incident to a human. `asset.team` was resolved at write time, so this is
one query rather than an export and a spreadsheet.

```sql
source = traces-agent-*
| where context.hash = '<hash>'
| stats count() as spans, dc(session.id) as sessions by gen_ai.agent.id, asset.team, asset.owner
| sort - spans
```

## 11 · Cross-region, for the multi-region slide

Slide 30. Same hunt, three regions, no data movement. `skip_unavailable` is the
whole point: an incident in one region must not blind the hunt in the other two.

```sql
source = traces-agent-*, eu-west-1:traces-agent-*, ap-south-1:traces-agent-*
| where context.hash = '<hash>'
| stats count() by gen_ai.agent.id, cloud.region
```

Single-node demo cluster has no remotes configured, so this one is for the slide
rather than the stage. `PUT _cluster/settings` with `cluster.remote.*` if you
ever want to wire it up.

---

## The same hunts as DSL

For anyone in the audience who does not have PPL enabled. Blast radius:

```json
POST traces-agent-*/_search
{ "size": 0,
  "query": { "term": { "context.hash": "<hash>" } },
  "aggs": { "agents": { "terms": { "field": "gen_ai.agent.id", "size": 50 },
                        "aggs": { "first_seen": { "min": { "field": "@timestamp" } } } } } }
```

Pacing:

```json
POST traces-agent-*/_search
{ "size": 0,
  "query": { "bool": { "filter": [ { "term": { "gen_ai.tool.name": "http_fetch" } } ] } },
  "aggs": { "pair": { "composite": { "size": 500, "sources": [
              { "agent": { "terms": { "field": "gen_ai.agent.id" } } },
              { "host":  { "terms": { "field": "url.domain" } } } ] },
            "aggs": { "out": { "sum": { "field": "http.request.body.size" } },
                      "cv":  { "avg": { "field": "agent.pace_cv" } } } } } }
```

That second one is the monitor's input verbatim — the hunt became the detection,
which is slide 19's third layer in one sentence.
