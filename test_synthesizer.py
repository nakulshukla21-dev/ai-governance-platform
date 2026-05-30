"""Tests for synthesizer.py (no API calls)."""

from __future__ import annotations

from synthesizer import (
    CandidateRule,
    _parse_candidate,
    _wrap_llm_prompt,
    candidate_to_policy,
    unique_policy_id,
)


def test_unique_policy_id_dedupes() -> None:
    existing = {"pii-detection"}
    assert unique_policy_id("pii-detection", existing) == "pii-detection-2"


def test_wrap_llm_prompt_adds_text_marker() -> None:
    wrapped = _wrap_llm_prompt("Classify harmful content.")
    assert "{text}" in wrapped


def test_candidate_to_policy_llm_defaults() -> None:
    candidate = CandidateRule(
        obligation_text="Do not disclose SSNs in chat.",
        suggested_id="ssn-rule",
        suggested_name="SSN Rule",
        suggested_description="Blocks SSN disclosure.",
        detection_method="llm",
        suggested_threshold_input=0.9,
        suggested_threshold_output=0.8,
        suggested_action="block",
        suggested_scope="both",
        suggested_llm_prompt="Detect social security numbers.",
        confidence="high",
        candidate_key="c0",
    )
    policy = candidate_to_policy(candidate, existing_ids=set())
    assert policy["id"] == "ssn-rule"
    assert policy["scope"] == ["input", "output"]
    assert policy["thresholds"]["input"] == 0.9
    assert "{text}" in policy["llm_prompt"]
    assert policy["detection_method"] == "llm"


def test_parse_candidate_minimal() -> None:
    raw = {
        "obligation_text": "Operators must log model changes.",
        "suggested_id": "model-logging",
        "suggested_name": "Model Logging",
        "suggested_description": "Requires change logs.",
        "detection_method": "llm",
        "suggested_action": "warn",
        "suggested_scope": "input",
        "suggested_llm_prompt": "Check for model change logging requirements.",
        "confidence": "medium",
    }
    candidate = _parse_candidate(raw, 0)
    assert candidate is not None
    assert candidate.suggested_scope == "input"
    assert candidate.confidence == "medium"
