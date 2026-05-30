"""Tests for policy_validation module."""

from __future__ import annotations

import pytest

from policy_validation import (
    validate_policies_doc,
    validate_regex_pattern,
    validate_upload_size,
)


def _minimal_policy(**overrides) -> dict:
    base = {
        "id": "test-policy",
        "name": "Test",
        "description": "Test policy",
        "enabled": True,
        "scope": ["input"],
        "action": "warn",
        "severity": "low",
        "detection_method": "llm",
        "thresholds": {"input": 0.75},
        "patterns": [],
        "llm_prompt": "Return JSON with detected and violation_confidence.",
    }
    base.update(overrides)
    return base


def test_validate_upload_size_rejects_large_file() -> None:
    assert validate_upload_size(b"x" * 2_000_000) is not None


def test_validate_policies_doc_accepts_minimal_valid_doc() -> None:
    doc = {"version": "1.0.0", "policies": [_minimal_policy()]}
    assert validate_policies_doc(doc) == []


def test_validate_policies_doc_rejects_duplicate_ids() -> None:
    doc = {
        "policies": [
            _minimal_policy(id="dup"),
            _minimal_policy(id="dup", name="Other"),
        ]
    }
    errors = validate_policies_doc(doc)
    assert any("duplicate" in e for e in errors)


def test_validate_policies_doc_requires_thresholds_for_llm() -> None:
    policy = _minimal_policy(thresholds={})
    errors = validate_policies_doc({"policies": [policy]})
    assert any("requires thresholds" in e for e in errors)


def test_validate_regex_pattern_rejects_invalid() -> None:
    assert validate_regex_pattern("[unclosed") is not None


def test_validate_regex_pattern_rejects_nested_quantifiers() -> None:
    assert validate_regex_pattern("(a+)+") is not None


def test_validate_regex_pattern_accepts_safe_pattern() -> None:
    assert validate_regex_pattern(r"\b\d{3}-\d{2}-\d{4}\b") is None
