"""Tests for server scan ordering and short-circuit helpers."""

from __future__ import annotations

import server


def test_policy_scan_groups_block_first() -> None:
    policies = [
        {"id": "warn", "action": "warn"},
        {"id": "block-a", "action": "block"},
        {"id": "redact", "action": "redact"},
        {"id": "block-b", "action": "block"},
    ]
    block, other = server._policy_scan_groups(policies)
    assert [p["id"] for p in block] == ["block-a", "block-b"]
    assert [p["id"] for p in other] == ["warn", "redact"]


def test_is_blocking_result() -> None:
    assert server._is_blocking_result({"detected": True, "action": "block"})
    assert not server._is_blocking_result({"detected": True, "action": "warn"})
    assert not server._is_blocking_result({"detected": False, "action": "block"})


def test_skip_llm_after_regex_block() -> None:
    policy = {"action": "block"}
    regex_hit = {"matched": True}
    assert server._skip_llm_after_regex_block(policy, regex_hit)
    assert not server._skip_llm_after_regex_block(
        {"action": "warn"}, regex_hit
    )
