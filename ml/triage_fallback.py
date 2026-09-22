"""
Scripted triage runner - the deterministic twin of the ML Commons agent.

Slide 24 says the triage agent "runs the four hunts a human would: pace, blast
radius, API delta, owner", then writes a summary and a recommendation, and that
a human revokes because the agent has no revoke tool. This module runs exactly
those four hunts as queries and produces the same summary.

It exists for two reasons. It is the fallback when Bedrock is unreachable from
a conference network, so the last beat of the demo never depends on the venue
wifi. And it is the honest control: it shows how much of "an agent triaged it"
is the four queries, and how much is the language model. The answer is that the
queries do the work; the model writes the paragraph.
"""

from __future__ import annotations

import json
from typing import Any

TOOL_ALLOW_LIST = ["read_file", "write_file", "git_push", "http_fetch"]


def _rows(result: dict) -> list[dict]:
    """PPL jdbc response -> list of dicts."""
    schema = [c["name"] for c in result.get("schema", [])]
    return [dict(zip(schema, row)) for row in result.get("datarows", [])]


class ScriptedTriage:
    def __init__(self, os_, poison_hash: str, entity: str):
        self.os = os_
        self.poison_hash = poison_hash
        self.entity = entity
        self.findings: dict[str, Any] = {}

    # -- hunt 1: is it a metronome? ------------------------------------------ #
    def hunt_pace(self) -> list[dict]:
        result = self.os.ppl(
            "source = traces-agent-* "
            "| where gen_ai.tool.name = 'http_fetch' "
            "| stats sum(http.request.body.size) as out, "
            "        stddev_samp(http.request.body.size) as jitter, "
            "        avg(agent.pace_cv) as pace, "
            "        count() as n "
            "  by gen_ai.agent.id, url.domain "
            "| where n > 8 and pace < 0.15 "
            "| sort - n | head 10"
        )
        rows = _rows(result)
        self.findings["pace"] = rows
        return rows

    # -- hunt 2: who else read the poison? ----------------------------------- #
    def hunt_blast_radius(self) -> list[dict]:
        result = self.os.search(
            "traces-agent-*",
            {
                "size": 0,
                "query": {"term": {"context.hash": self.poison_hash}},
                "aggs": {
                    "agents": {
                        "terms": {"field": "gen_ai.agent.id", "size": 50},
                        "aggs": {"first_seen": {"min": {"field": "@timestamp"}}},
                    }
                },
            },
        )
        rows = [
            {"agent": b["key"], "reads": b["doc_count"], "first_seen": b["first_seen"]["value_as_string"]}
            for b in result["aggregations"]["agents"]["buckets"]
        ]
        self.findings["blast_radius"] = rows
        return rows

    # -- hunt 3: which of them moved on to the credentials? ------------------ #
    def hunt_api_delta(self, agents: list[str]) -> list[dict]:
        result = self.os.search(
            "logs-sec-cloudtrail",
            {
                "size": 0,
                "query": {"terms": {"agent.id": agents}},
                "aggs": {
                    "agents": {
                        "terms": {"field": "agent.id", "size": 50},
                        "aggs": {
                            "api_calls": {"cardinality": {"field": "event.action"}},
                            "actions": {"terms": {"field": "event.action", "size": 12}},
                        },
                    }
                },
            },
        )
        rows = []
        for bucket in result["aggregations"]["agents"]["buckets"]:
            rows.append(
                {
                    "agent": bucket["key"],
                    "distinct_api_calls": bucket["api_calls"]["value"],
                    "actions": [a["key"] for a in bucket["actions"]["buckets"]],
                }
            )
        rows.sort(key=lambda r: -r["distinct_api_calls"])
        self.findings["api_delta"] = rows
        return rows

    # -- hunt 4: who owns it? ------------------------------------------------ #
    def hunt_owner(self, agent_id: str) -> dict:
        result = self.os.search(
            "asset-owner",
            {"size": 1, "query": {"term": {"gen_ai.agent.id": agent_id}}},
        )
        hits = result["hits"]["hits"]
        owner = hits[0]["_source"] if hits else {}
        self.findings["owner"] = owner
        return owner

    # -- the paragraph a human reads ----------------------------------------- #
    def run(self) -> str:
        pace = self.hunt_pace()
        radius = self.hunt_blast_radius()
        agents = [r["agent"] for r in radius]
        delta = self.hunt_api_delta(agents) if agents else []
        owner = self.hunt_owner(self.entity)

        metronomes = [r for r in pace if r.get("gen_ai.agent.id") == self.entity]
        escalated = [r for r in delta if r["distinct_api_calls"] >= 5]
        baseline = [r for r in delta if r["distinct_api_calls"] < 5]

        asset = owner.get("asset", {})
        lines = [
            f"FINDING  agent-egress-pace on {self.entity}",
            "",
            "1. Pace.",
        ]
        if metronomes:
            m = metronomes[0]
            lines.append(
                f"   {self.entity} -> {m.get('url.domain')}: {int(m.get('n', 0))} calls, "
                f"{int(m.get('out', 0)):,} bytes out, pacing CV {float(m.get('pace', 0)):.3f}. "
                f"Real agents think, fetch, write, wait. This one did not."
            )
        else:
            lines.append(f"   No flat-line pattern currently visible for {self.entity}.")

        lines += [
            "",
            "2. Blast radius.",
            f"   context.hash {self.poison_hash[:16]}... was read by {len(radius)} agents: "
            f"{', '.join(sorted(a for a in agents))}.",
            "",
            "3. API delta.",
        ]
        if escalated:
            for row in escalated:
                lines.append(
                    f"   {row['agent']}: {row['distinct_api_calls']} distinct API actions "
                    f"({', '.join(row['actions'][:5])}...)"
                )
            lines.append(
                f"   The other {len(baseline)} readers stayed at "
                f"{max((r['distinct_api_calls'] for r in baseline), default=0)} or fewer. "
                f"Nine agents read the README. One moved on to the credentials."
            )
        else:
            lines.append("   No widening of the cloud API surface among the readers.")

        lines += [
            "",
            "4. Owner.",
            f"   {asset.get('team', 'unknown')} / {asset.get('owner', 'unknown')} "
            f"(criticality: {asset.get('criticality', 'unknown')}), "
            f"instance {owner.get('cloud', {}).get('instance', {}).get('id', 'unknown')}.",
            "",
            "RECOMMENDATION",
            f"   Revoke the instance role session for {self.entity} and pause its task queue.",
            "   Re-scan the other readers for outbound POSTs to health endpoints before releasing them.",
            "   Quarantine the upstream README until the mirror is re-signed.",
            "",
            "   This agent has no revoke tool. A human makes that call.",
        ]
        return "\n".join(lines)


def run_real_agent(os_, agent_id: str, entity: str, poison_hash: str) -> tuple[str, dict]:
    """Execute the registered ML Commons agent. Returns (text, token_usage)."""
    question = (
        f"An anomaly detector graded agent {entity} on the agent-egress-pace detector. "
        f"Triage it in four steps and be specific. "
        f"(1) Pace: query traces-agent-* for that agent's http_fetch calls and report call count, "
        f"total bytes out and the average of agent.pace_cv, grouped by url.domain. "
        f"(2) Blast radius: how many distinct agents have context.hash = '{poison_hash}'? Name them. "
        f"(3) API delta: for those agents, how many distinct event.action values appear in "
        f"logs-sec-cloudtrail, and which agent has the most? "
        f"(4) Owner: look up the owning team and criticality for {entity} in the asset-owner index. "
        f"Finish with a recommendation. You cannot revoke anything; a human does that."
    )
    result = os_.post(
        f"_plugins/_ml/agents/{agent_id}/_execute",
        {"parameters": {"question": question, "verbose": False, "include_token_usage": True}},
    )
    text = json.dumps(result)
    usage = {}
    inference = result.get("inference_results") or [{}]
    for output in inference[0].get("output", []):
        if output.get("name") in {"response", "memory_id"} and isinstance(output.get("result"), str):
            if output["name"] == "response":
                text = output["result"]
        if output.get("name") == "token_usage":
            usage = output.get("dataAsMap", {})
    return text, usage
