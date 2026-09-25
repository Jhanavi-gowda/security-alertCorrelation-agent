"""
Security Alert Correlation Agent
=================================

The core idea: instead of three security tools each raising an independent,
context-free alert, one agent can query all three, notice they share an
identity and a time window, and describe them as a SINGLE incident.

Two modes:
  --mock   Runs a simple rule-based correlation pass with no API key needed.
           Useful for verifying the data plumbing and for anyone reading
           this repo without wanting to spend API credits.
  (default) Uses an LLM with tool-calling to decide which sources to query
           and reason about what's connected. Requires ANTHROPIC_API_KEY.

Usage:
    python agent.py --mock
    python agent.py                      # requires ANTHROPIC_API_KEY env var
"""

import argparse
import json
import os
from datetime import datetime, timedelta

from sources.implementations import IdentitySource, EndpointSource, CloudAuditSource

WINDOW_START = "2026-09-25T00:00:00"
WINDOW_END = "2026-09-27T00:00:00"

SOURCES = {
    "identity": IdentitySource(),
    "endpoint": EndpointSource(),
    "cloud_audit": CloudAuditSource(),
}

# ---------------------------------------------------------------------------
# Tool definitions — what the LLM is allowed to call
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "name": "query_identity_logs",
        "description": "Query Entra ID sign-in events (logins, MFA challenges, location, IP) within a time range.",
        "input_schema": {
            "type": "object",
            "properties": {
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
            },
            "required": ["start_time", "end_time"],
        },
    },
    {
        "name": "query_endpoint_logs",
        "description": "Query endpoint/EDR events (process creation, host activity) within a time range.",
        "input_schema": {
            "type": "object",
            "properties": {
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
            },
            "required": ["start_time", "end_time"],
        },
    },
    {
        "name": "query_cloud_audit_logs",
        "description": "Query cloud audit events (role assignments, resource changes) within a time range.",
        "input_schema": {
            "type": "object",
            "properties": {
                "start_time": {"type": "string"},
                "end_time": {"type": "string"},
            },
            "required": ["start_time", "end_time"],
        },
    },
]

TOOL_TO_SOURCE = {
    "query_identity_logs": "identity",
    "query_endpoint_logs": "endpoint",
    "query_cloud_audit_logs": "cloud_audit",
}


def execute_tool(tool_name: str, tool_input: dict) -> list:
    source = SOURCES[TOOL_TO_SOURCE[tool_name]]
    return source.fetch_alerts(tool_input["start_time"], tool_input["end_time"])


SYSTEM_PROMPT = """You are a security correlation analyst. You have three tools \
that each query a different log source: identity (sign-ins), endpoint (process \
activity), and cloud_audit (role/resource changes).

Your job: pull alerts from all three sources for the given window, then find \
events that are actually ONE incident — the same identity, an overlapping or \
tightly sequential time window, and a plausible attack narrative (e.g. an \
anomalous login followed by suspicious process execution followed by a \
privilege change by the same user).

Most events are unrelated noise. Do not force a correlation that isn't there.

When you find a correlated chain, respond with a JSON object:
{
  "incident_found": true/false,
  "correlated_events": [ ... the raw events you grouped ... ],
  "reasoning": "why these belong together",
  "severity": "Low" | "Medium" | "High" | "Critical",
  "recommended_action": "..."
}
"""


def run_with_llm(start_time: str, end_time: str) -> dict:
    """Requires ANTHROPIC_API_KEY. Uses tool-calling so the model decides
    which sources to pull and reasons over the combined result."""
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    messages = [{
        "role": "user",
        "content": f"Investigate the window {start_time} to {end_time}. "
                   f"Pull all three sources and report any correlated incident."
    }]

    for _ in range(6):  # bounded loop — a real agent needs a hard stop
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        if response.stop_reason != "tool_use":
            # model produced its final answer
            final_text = "".join(b.text for b in response.content if b.type == "text")
            return {"raw_model_output": final_text}

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = execute_tool(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result),
                })
        messages.append({"role": "user", "content": tool_results})

    return {"error": "exceeded tool-call loop limit without a final answer"}


def run_mock(start_time: str, end_time: str) -> dict:
    """No API key needed. A simple heuristic stand-in for the LLM's reasoning:
    group events across sources that share an identity within a tight window.
    This exists so the data plumbing and interface design can be verified
    without spending API credits — it is NOT the actual agent logic."""
    all_events = []
    for source_name, source in SOURCES.items():
        for event in source.fetch_alerts(start_time, end_time):
            mapping = source.get_field_mapping()
            identity = event.get(mapping.get("identity", ""))
            all_events.append({"source": source_name, "identity": identity, **event})

    by_identity = {}
    for e in all_events:
        if e["identity"]:
            by_identity.setdefault(e["identity"], []).append(e)

    # flag any identity with events in >=2 distinct sources within the window
    correlated = {
        identity: events for identity, events in by_identity.items()
        if len({e["source"] for e in events}) >= 2
    }

    if not correlated:
        return {"incident_found": False, "reasoning": "No identity appears across multiple sources."}

    identity, events = max(correlated.items(), key=lambda kv: len(kv[1]))
    return {
        "incident_found": True,
        "correlated_events": events,
        "reasoning": f"Identity '{identity}' has events across "
                     f"{len({e['source'] for e in events})} sources in this window.",
        "severity": "High",
        "recommended_action": "Escalate for manual review — cross-source identity activity detected.",
        "note": "Generated by rule-based --mock fallback, not the LLM agent.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true", help="Run without calling an LLM API")
    parser.add_argument("--start", default=WINDOW_START)
    parser.add_argument("--end", default=WINDOW_END)
    args = parser.parse_args()

    if args.mock:
        result = run_mock(args.start, args.end)
    else:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("ANTHROPIC_API_KEY not set. Run with --mock to test without an API key.")
            return
        result = run_with_llm(args.start, args.end)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
