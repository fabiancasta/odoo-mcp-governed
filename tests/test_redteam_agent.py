"""The LLM red-team agent's loop, with a scripted model and a fake server.

No network and no model: this checks the plumbing the verdict depends on —
tool calls are executed, refusals counted, and a canary is caught whether it
comes back plain or base64-encoded.
"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "redteam_agent", Path(__file__).parent.parent / "redteam" / "agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

CANARIES = {"config_parameter": "CANARY-PARAM-abc", "cron_attachment": "CANARY-FILE-xyz"}


class FakeGoverned:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def tools(self):
        return [{"name": "search_records", "description": "d",
                 "inputSchema": {"type": "object", "properties": {}}}]

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        return self.answers.pop(0)


def scripted(*steps):
    steps = list(steps)

    def complete(messages, tools):
        assert tools[0]["function"]["name"] == "search_records"
        return steps.pop(0)
    return complete


def tool_turn(*arguments):
    return {"role": "assistant", "content": None, "tool_calls": [
        {"id": f"c{i}", "type": "function",
         "function": {"name": "search_records", "arguments": json.dumps(a)}}
        for i, a in enumerate(arguments)]}


def run(governed, complete):
    log = []
    outcome = agent.attack(governed, complete, turns=5, canaries=CANARIES, log=log.append)
    return outcome, log


def test_a_clean_run_counts_calls_and_keeps_the_report() -> None:
    governed = FakeGoverned([(True, "Refused by policy: no"), (False, '{"records": []}')])
    outcome, log = run(governed, scripted(
        tool_turn({"model": "ir.config_parameter"}, {"model": "res.partner"}),
        {"role": "assistant", "content": "Everything was refused."},
    ))
    assert outcome["stats"] == {"calls": 2, "refused": 1, "allowed": 1}
    assert outcome["leaks"] == []
    assert outcome["report"] == "Everything was refused."
    assert len(log) == 3


def test_a_plain_canary_in_a_result_is_a_leak() -> None:
    governed = FakeGoverned([(False, '{"value": "CANARY-PARAM-abc"}')])
    outcome, _ = run(governed, scripted(tool_turn({}), {"role": "assistant", "content": "got it"}))
    assert outcome["leaks"] == [{"turn": 0, "tool": "search_records",
                                 "canaries": ["config_parameter"]}]


def test_a_base64_canary_is_a_leak_too() -> None:
    encoded = base64.b64encode(b"CANARY-FILE-xyz").decode()
    governed = FakeGoverned([(False, f'{{"datas": "{encoded}"}}')])
    outcome, _ = run(governed, scripted(tool_turn({}), {"role": "assistant", "content": "ok"}))
    assert outcome["leaks"][0]["canaries"] == ["cron_attachment"]


def test_malformed_tool_arguments_do_not_crash_the_run() -> None:
    governed = FakeGoverned([(True, "Invalid arguments")])
    bad = {"role": "assistant", "content": None, "tool_calls": [
        {"id": "x", "type": "function", "function": {"name": "search_records",
                                                     "arguments": "{not json"}}]}
    outcome, _ = run(governed, scripted(bad, {"role": "assistant", "content": "done"}))
    assert governed.calls == [("search_records", {})]
    assert outcome["stats"]["calls"] == 1


def test_the_window_keeps_the_head_and_never_orphans_a_tool_result() -> None:
    head = [{"role": "system", "content": "s"}, {"role": "user", "content": "go"}]
    history = []
    for i in range(20):
        history.append({"role": "assistant", "content": None, "tool_calls": [
            {"id": f"c{i}", "type": "function", "function": {"name": "t", "arguments": "{}"}}]})
        history.append({"role": "tool", "tool_call_id": f"c{i}", "content": "x" * 400})
    sent = agent.window(head + history, budget_chars=3_000)
    assert sent[:2] == head
    assert sent[2]["role"] == "assistant"
    assert len(sent) < len(head + history)
    calls = {c["id"] for m in sent if m.get("tool_calls") for c in m["tool_calls"]}
    assert all(m["tool_call_id"] in calls for m in sent if m["role"] == "tool")
