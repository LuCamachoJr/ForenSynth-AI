import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from forensynth.llm import prompt_blocks, synthesize


def config(**updates):
    return {
        "model": "gpt-5-mini",
        "max_input_tokens": 16000,
        "max_output_tokens": 1024,
        "max_total_tokens": 100000,
        "max_requests": 20,
        "timeout": 10,
        "input_rate": None,
        "output_rate": None,
    } | updates


def fake_client(valid=True):
    def create(**kwargs):
        supplied = json.loads(kwargs["messages"][1]["content"])["records"]
        refs = [record["detection"]["id"] for record in supplied]
        item = {
            "statement": "Possible authorized PowerShell execution",
            "evidence_refs": refs if valid else ["invented"],
            "classification": "inferred",
            "confidence": "low",
            "confidence_rationale": "Needs human context",
            "alternative_explanations": ["Authorized simulation"],
        }
        return SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=50),
            choices=[
                SimpleNamespace(
                    finish_reason="stop",
                    message=SimpleNamespace(refusal=None, content=json.dumps({"findings": [item]})),
                )
            ],
        )

    return SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=Mock(side_effect=create)))
    )


def test_valid_findings_pending_and_usage_accumulates(document):
    client = fake_client()
    findings, processed, skipped, meta, _ = synthesize(
        document, document["detections"], config(input_rate=1, output_rate=2), client
    )
    assert len(processed) == 3 and not skipped
    assert all(f["review_status"] == "pending" for f in findings)
    calls = client.chat.completions.create.call_count
    assert meta["usage"]["gpt-5-mini"] == {"input_tokens": 100 * calls, "output_tokens": 50 * calls}
    assert meta["estimated_cost_usd"] == pytest.approx(calls * 0.0002)


def test_invalid_references_rejected_but_usage_recorded(document):
    findings, processed, skipped, meta, warnings = synthesize(
        document, document["detections"], config(), fake_client(False)
    )
    assert not findings and not processed and len(skipped) == 3
    assert meta["usage"]["gpt-5-mini"]["input_tokens"] > 0 and warnings
    assert meta["estimated_cost_usd"] is None


def test_request_budget_caps_calls(document):
    client = fake_client()
    _, processed, skipped, meta, _ = synthesize(
        document, document["detections"], config(max_requests=1), client
    )
    assert client.chat.completions.create.call_count == 1
    assert len(processed) + len(skipped) == 3
    assert meta["requests_attempted"] == 1


def test_token_budget_prevents_call(document):
    client = fake_client()
    _, processed, skipped, _, _ = synthesize(
        document, document["detections"], config(max_total_tokens=10), client
    )
    assert client.chat.completions.create.call_count == 0
    assert not processed and len(skipped) == 3


def test_oversized_input_not_silently_sent(document):
    client = fake_client()
    _, processed, skipped, _, _ = synthesize(
        document, document["detections"], config(max_input_tokens=10), client
    )
    assert client.chat.completions.create.call_count == 0
    assert not processed and len(skipped) == 3


def test_prompt_truncation_disclosed(document):
    document["events"][0]["process"]["ScriptBlockText"] = "x" * 3000
    blocks, _, _, _ = prompt_blocks(document, document["detections"], 16000, "gpt-5-mini")
    first = next(
        e
        for block in blocks
        for item in block
        for e in item["events"]
        if e["id"] == document["events"][0]["id"]
    )
    assert len(first["process"]["ScriptBlockText"]) == 2000
    assert "ScriptBlockText" in first["truncated_fields"]
    assert len(document["events"][0]["process"]["ScriptBlockText"]) == 3000
